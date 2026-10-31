use std::collections::HashMap;
use std::sync::Arc;

use crate::support::{TestError, common::MemoryStore};
use bitcoin_rs_index::types::ScriptHistoryOccurrence;
use bitcoin_rs_index::{
    IndexCapabilities, IndexError, IndexReader, IndexWatermark, IndexWriter, Indexer, ScriptHash,
    SpentCoinScripts,
};
use bitcoin_rs_primitives::{Hash256, encode};
use bitcoin_rs_storage::{ColumnFamily, KvStore, PrefixScanLimit};

const BLOCKS: u32 = 12;

const SCAN_ALL: PrefixScanLimit = PrefixScanLimit {
    max_rows: 100_000,
    max_bytes: 64 << 20,
};

fn script_for(seed: u32) -> Vec<u8> {
    let mut script = Vec::with_capacity(22);
    script.push(0x00);
    script.push(0x14);
    script.extend_from_slice(&[0x11; 20]);
    script[2] = u8::try_from(seed % 251).unwrap_or(0);
    script[3] = u8::try_from((seed / 251) % 251).unwrap_or(0);
    script
}

#[derive(Default)]
struct ChainScripts {
    by_txid: HashMap<[u8; 32], Vec<u8>>,
}

impl SpentCoinScripts for ChainScripts {
    fn script_bytes(&self, txid: &[u8; 32], _vout: u32) -> Option<&[u8]> {
        self.by_txid.get(txid).map(Vec::as_slice)
    }
}

struct Chain {
    blocks: Vec<Vec<u8>>,
    hashes: Vec<Hash256>,
    coinbase_txids: Vec<[u8; 32]>,
    spend_txids: Vec<[u8; 32]>,
    scripts: ChainScripts,
}

fn push_tx(body: &mut Vec<u8>, tx: &[u8]) {
    body.extend_from_slice(tx);
}

fn build_chain() -> Chain {
    let capacity = usize::try_from(BLOCKS).unwrap_or(0);
    let mut blocks = Vec::with_capacity(capacity);
    let mut hashes = Vec::with_capacity(capacity);
    let mut coinbase_txids = Vec::with_capacity(capacity);
    let mut spend_txids = Vec::with_capacity(capacity);
    let mut scripts = ChainScripts::default();
    let mut previous = Hash256::from_le_bytes(&[0; 32]);

    for height in 0..BLOCKS {
        let coinbase_script = script_for(height);
        let mut coinbase = Vec::new();
        coinbase.extend_from_slice(&1_u32.to_le_bytes());
        coinbase.push(0x01);
        coinbase.extend_from_slice(&[0_u8; 32]);
        coinbase.extend_from_slice(&u32::MAX.to_le_bytes());
        coinbase.push(0x02);
        coinbase.extend_from_slice(&[u8::try_from(height % 251).unwrap_or(0), 0xFF]);
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
            let spend_script = script_for(1_000 + height);
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
        body.extend_from_slice(&previous.to_le_bytes());
        body.extend_from_slice(&[0_u8; 32]);
        body.extend_from_slice(&(1_600_000_000_u32.saturating_add(height)).to_le_bytes());
        body.extend_from_slice(&0x207F_FFFF_u32.to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.push(u8::try_from(1 + usize::from(height > 0)).unwrap_or(0));
        push_tx(&mut body, &coinbase);
        if height > 0 {
            push_tx(&mut body, &spend);
        }
        let hash = encode::double_sha256(&body[..80]);
        blocks.push(body);
        hashes.push(hash);
        previous = hash;
    }

    Chain {
        blocks,
        hashes,
        coinbase_txids,
        spend_txids,
        scripts,
    }
}

fn commit_chain<S>(
    writer: &mut IndexWriter<S>,
    chain: &Chain,
) -> Result<Vec<IndexWatermark>, IndexError>
where
    S: KvStore + 'static,
{
    let mut watermarks = Vec::with_capacity(chain.blocks.len());
    for (height, body) in chain.blocks.iter().enumerate() {
        let Some(hash) = chain.hashes.get(height) else {
            return Err(IndexError::NonContiguousPrepared { watermark: None });
        };
        let prepared = writer.prepare_block_with_spent_scripts(
            IndexCapabilities::HISTORICAL,
            u32::try_from(height).unwrap_or(0),
            hash.to_le_bytes(),
            body,
            &chain.scripts,
        )?;
        let mut batch =
            bitcoin_rs_index::PreparedBatch::new(bitcoin_rs_index::PreparedBatchLimits {
                max_rows: usize::MAX,
                max_bytes: usize::MAX,
            });
        assert!(
            batch.try_push(prepared).is_ok(),
            "one block per batch is admitted"
        );
        watermarks.push(writer.commit_forward(batch)?);
    }
    Ok(watermarks)
}

fn occurred(
    rows: &[bitcoin_rs_index::TxIndexScanRow],
    scripthash: ScriptHash,
) -> Vec<(u32, [u8; 32], u8)> {
    let mut found = Vec::new();
    for row in rows {
        let height = row.row.height();
        for occurrence in ScriptHistoryOccurrence::decode_all(&row.value).unwrap_or_default() {
            if occurrence.scripthash == scripthash {
                found.push((height, occurrence.txid, occurrence.flags));
            }
        }
    }
    found.sort_unstable();
    found
}

// IDX-02, IDX-09
#[test]
fn writer_stores_one_occurrence_per_script_height_and_transaction() -> Result<(), TestError> {
    let chain = build_chain();
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    commit_chain(&mut writer, &chain)?;

    let indexer = Indexer::new(Arc::clone(&store));
    let snapshot = indexer.snapshot()?;
    let script = ScriptHash::from_script_bytes(&script_for(0));
    let rows = snapshot.funding_rows_from(script, u32::MAX, SCAN_ALL)?;
    assert!(rows.complete, "one bounded scan covers the fixture");
    assert_eq!(
        occurred(&rows.rows, script),
        vec![
            (0, chain.coinbase_txids[0], ScriptHistoryOccurrence::FUNDING),
            (1, chain.spend_txids[0], ScriptHistoryOccurrence::SPENDING),
        ],
        "the coinbase funds at 0 and the block-1 spend is keyed by the same script"
    );

    let payment = ScriptHash::from_script_bytes(&script_for(1_001));
    let rows = snapshot.funding_rows_from(payment, u32::MAX, SCAN_ALL)?;
    let occurrences = occurred(&rows.rows, payment);
    assert_eq!(occurrences.len(), 1, "the payment is funded once");
    assert_eq!(
        occurrences[0].0, 1,
        "the occurrence keeps its confirming height"
    );
    Ok(())
}

// IDX-06
#[test]
fn rollback_removes_exactly_the_disconnected_block_rows() -> Result<(), TestError> {
    let chain = build_chain();
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let watermarks = commit_chain(&mut writer, &chain)?;
    let script = ScriptHash::from_script_bytes(&script_for(0));

    let last_arg = watermarks
        .iter()
        .rev()
        .nth(1)
        .copied()
        .ok_or("fixture needs at least two blocks")?;
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
        fence,
        IndexCapabilities::HISTORICAL,
        Some(last_arg),
        chain
            .blocks
            .last()
            .ok_or("fixture needs at least one block")?,
        bitcoin_rs_index::ConsumerCursorUpdate::Keep,
        &chain.scripts,
    )?;

    let indexer = Indexer::new(Arc::clone(&store));
    let snapshot = indexer.snapshot()?;
    let rows = snapshot.funding_rows_from(script, u32::MAX, SCAN_ALL)?;
    assert_eq!(
        occurred(&rows.rows, script),
        vec![
            (0, chain.coinbase_txids[0], ScriptHistoryOccurrence::FUNDING),
            (1, chain.spend_txids[0], ScriptHistoryOccurrence::SPENDING),
        ],
        "the disconnected spend no longer names the script"
    );
    assert_eq!(
        writer.watermark()?,
        watermarks.iter().rev().nth(1).copied(),
        "the watermark moves back one height"
    );
    Ok(())
}

// IDX-05, IDX-10
#[test]
fn reopen_serves_the_same_occurrence_rows() -> Result<(), TestError> {
    let chain = build_chain();
    let store = Arc::new(MemoryStore::default());
    let script = ScriptHash::from_script_bytes(&script_for(3));
    let before = {
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        commit_chain(&mut writer, &chain)?;
        let indexer = Indexer::new(Arc::clone(&store));
        let snapshot = indexer.snapshot()?;
        occurred(
            &snapshot.funding_rows_from(script, u32::MAX, SCAN_ALL)?.rows,
            script,
        )
    };
    let writer = IndexWriter::open(Arc::clone(&store), 1)?;
    assert_eq!(
        writer.watermark()?,
        Some(IndexWatermark {
            height: BLOCKS - 1,
            hash: chain.hashes[chain.hashes.len() - 1].to_le_bytes(),
        }),
        "reopen keeps the committed watermark"
    );
    drop(writer);
    let indexer = Indexer::new(Arc::clone(&store));
    let snapshot = indexer.snapshot()?;
    let after = occurred(
        &snapshot.funding_rows_from(script, u32::MAX, SCAN_ALL)?.rows,
        script,
    );
    assert_eq!(after, before, "reopen serves identical occurrence rows");
    Ok(())
}

// IDX-05
#[test]
fn format_5_marker_refuses_and_rebuilds_the_derived_store() -> Result<(), TestError> {
    let chain = build_chain();
    let store = Arc::new(MemoryStore::default());
    store.put(
        ColumnFamily::UtxoMeta,
        &[0x00, b'V'],
        &[0x05, 0x00, 0x00, 0x00],
    )?;
    assert!(
        matches!(
            IndexWriter::open(Arc::clone(&store), 1),
            Err(IndexError::UnsupportedTxIndexFormatVersion { version: 5 })
        ),
        "a format-5 marker refuses open"
    );

    IndexWriter::reset_index(store.as_ref(), 1)?;
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    assert_eq!(writer.watermark()?, None, "reset leaves no watermark");
    commit_chain(&mut writer, &chain)?;
    let script = ScriptHash::from_script_bytes(&script_for(0));
    let indexer = Indexer::new(Arc::clone(&store));
    let snapshot = indexer.snapshot()?;
    assert_eq!(
        occurred(
            &snapshot.funding_rows_from(script, u32::MAX, SCAN_ALL)?.rows,
            script,
        )
        .len(),
        2,
        "the rebuilt store serves the same history"
    );
    Ok(())
}

// IDX-10
#[test]
fn failed_fenced_write_publishes_no_watermark_and_no_rows() -> Result<(), TestError> {
    let chain = build_chain();
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let first = writer.prepare_block_with_spent_scripts(
        IndexCapabilities::HISTORICAL,
        0,
        chain.hashes[0].to_le_bytes(),
        &chain.blocks[0],
        &chain.scripts,
    )?;
    let mut batch = bitcoin_rs_index::PreparedBatch::new(bitcoin_rs_index::PreparedBatchLimits {
        max_rows: usize::MAX,
        max_bytes: usize::MAX,
    });
    assert!(batch.try_push(first).is_ok(), "first block is admitted");
    writer.commit_forward(batch)?;
    let committed_rows = store.count(ColumnFamily::Funding);

    let second = writer.prepare_block_with_spent_scripts(
        IndexCapabilities::HISTORICAL,
        1,
        chain.hashes[1].to_le_bytes(),
        &chain.blocks[1],
        &chain.scripts,
    )?;
    let mut batch = bitcoin_rs_index::PreparedBatch::new(bitcoin_rs_index::PreparedBatchLimits {
        max_rows: usize::MAX,
        max_bytes: usize::MAX,
    });
    assert!(batch.try_push(second).is_ok(), "second block is admitted");
    store.arm_fenced_write_failure();
    assert!(
        writer.commit_forward(batch).is_err(),
        "the durability boundary reports the injected failure"
    );
    assert_eq!(
        writer.watermark()?,
        Some(IndexWatermark {
            height: 0,
            hash: chain.hashes[0].to_le_bytes(),
        }),
        "no newer watermark is published"
    );
    assert_eq!(
        store.count(ColumnFamily::Funding),
        committed_rows,
        "no row of the failed batch is visible"
    );
    Ok(())
}
