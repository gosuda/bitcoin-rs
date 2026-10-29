//! Atomic filter publication, selective reset, rollback and backend persistence.
#[path = "support/common.rs"]
mod common;

use bitcoin::{Block, consensus::serialize, hashes::Hash as _};
use bitcoin_rs_index::{
    ConsumerCursorUpdate, IndexCapabilities, IndexError, IndexReader, IndexWatermark, IndexWriter,
    PreparedBatch, PreparedBatchLimits, SpentCoinScripts,
};
use bitcoin_rs_storage::KvStore;
use std::sync::{Arc, atomic::Ordering};

struct NoSpends;
impl SpentCoinScripts for NoSpends {
    fn script_bytes(&self, _: &[u8; 32], _: u32) -> Option<&[u8]> {
        None
    }
}

fn prepare<S: KvStore>(
    writer: &IndexWriter<S>,
    block: &Block,
    height: u32,
    caps: IndexCapabilities,
) -> Result<PreparedBatch, IndexError> {
    let block = writer.prepare_block_with_spent_scripts(
        caps,
        height,
        block.block_hash().to_byte_array(),
        &serialize(block),
        &NoSpends,
    )?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 10_000,
    });
    assert!(batch.try_push(block).is_ok());
    Ok(batch)
}

#[test]
fn filter_rows_and_cursor_publish_atomically_and_reset_preserves_txindex()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(common::MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    assert!(matches!(
        writer.prepare_block_for(
            IndexCapabilities::COMPACT_FILTERS,
            0,
            genesis.block_hash().to_byte_array(),
            &serialize(&genesis)
        ),
        Err(IndexError::MissingSpentScripts)
    ));
    let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Testnet);
    let hash = genesis.block_hash().to_byte_array();
    let caps = IndexCapabilities::TX_LOOKUP.with_compact_filters(true);
    store.fail_next_fenced_write.store(true, Ordering::SeqCst);
    assert!(matches!(
        writer.commit_forward(prepare(&writer, &genesis, 0, caps)?),
        Err(IndexError::Storage(_))
    ));
    assert!(writer.watermarks()?.compact_filters.is_none());
    assert!(writer.snapshot()?.compact_filter(&hash)?.is_none());
    writer.commit_forward(prepare(&writer, &genesis, 0, caps)?)?;
    let original = writer
        .snapshot()?
        .compact_filter(&hash)?
        .ok_or("missing filter")?;
    assert_eq!(original.filter, [1, 0x9d, 0xfc, 0xa8]);
    let mark = Some(IndexWatermark { height: 0, hash });
    assert_eq!(writer.watermarks()?.compact_filters, mark);

    let mut child = genesis.clone();
    child.header.prev_blockhash = genesis.block_hash();
    child.header.nonce = child.header.nonce.wrapping_add(1);
    let stale_batch = prepare(&writer, &child, 1, IndexCapabilities::COMPACT_FILTERS)?;
    let stale_fence = writer.fenced_watermarks()?.0;
    writer.reset_capabilities(IndexCapabilities::COMPACT_FILTERS)?;
    assert_eq!(writer.watermarks()?.tx_lookup, mark);
    assert!(writer.snapshot()?.compact_filter(&hash)?.is_none());
    assert!(matches!(
        writer.commit_forward_with_cursor(stale_fence, stale_batch, ConsumerCursorUpdate::Keep),
        Err(IndexError::ResetInProgress)
    ));

    writer.commit_forward(prepare(
        &writer,
        &genesis,
        0,
        IndexCapabilities::COMPACT_FILTERS,
    )?)?;
    writer.commit_forward(prepare(
        &writer,
        &child,
        1,
        IndexCapabilities::COMPACT_FILTERS,
    )?)?;
    let fence = writer.fenced_watermarks()?.0;
    assert!(matches!(
        writer.commit_rollback_one_for_with_cursor(
            fence,
            IndexCapabilities::COMPACT_FILTERS,
            mark,
            &serialize(&child),
            ConsumerCursorUpdate::Keep,
        ),
        Err(IndexError::MissingSpentScripts)
    ));
    writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
        fence,
        IndexCapabilities::COMPACT_FILTERS,
        mark,
        &serialize(&child),
        ConsumerCursorUpdate::Keep,
        &NoSpends,
    )?;
    assert!(
        writer
            .snapshot()?
            .compact_filter(&child.block_hash().to_byte_array())?
            .is_none()
    );
    assert_eq!(
        writer.snapshot()?.compact_filter(&hash)?,
        Some(original.clone())
    );
    drop(writer);
    let reopened = IndexWriter::open(store, 2)?;
    assert_eq!(reopened.watermarks()?.compact_filters, mark);
    assert_eq!(reopened.snapshot()?.compact_filter(&hash)?, Some(original));
    Ok(())
}

#[cfg(feature = "redb")]
#[test]
fn compact_filters_survive_redb_index_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("index.redb");
    let block = bitcoin::constants::genesis_block(bitcoin::Network::Testnet);
    let hash = block.block_hash().to_byte_array();
    {
        let store = Arc::new(bitcoin_rs_storage::open_redb_tx_index_store(&path)?);
        let mut writer = IndexWriter::open(store, 1)?;
        writer.commit_forward(prepare(
            &writer,
            &block,
            0,
            IndexCapabilities::COMPACT_FILTERS,
        )?)?;
    }
    let store = Arc::new(bitcoin_rs_storage::open_redb_tx_index_store(&path)?);
    let writer = IndexWriter::open(store, 2)?;
    assert_eq!(
        writer
            .snapshot()?
            .compact_filter(&hash)?
            .ok_or("missing filter")?
            .filter,
        [1, 0x9d, 0xfc, 0xa8]
    );
    Ok(())
}
