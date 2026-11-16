//! Committed-facts rows and the batch byte limit: `PRJ-05`.

use crate::support::TestError;
use std::sync::Arc;

use bitcoin_rs_index::{
    HEADER_ROW_SIZE, IndexCapabilities, IndexWriter, PreparedBatch, PreparedBatchLimits,
};
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, TxFacts};
use bitcoin_rs_storage::{FactsScript, RocksDbStore};

fn coinbase_block(height: u32, outputs: u32) -> Result<CommittedBlock, TestError> {
    let mut created = Vec::new();
    for vout in 0..outputs {
        created.push(CreatedOutput {
            vout,
            value: 1_000 + u64::from(vout),
            script: FactsScript::copy_from_slice(&[0x51, u8::try_from(vout)?]),
        });
    }
    let mut txid = [0xC0; 32];
    txid[..4].copy_from_slice(&height.to_be_bytes());
    Ok(CommittedBlock {
        height,
        hash: [u8::try_from(height)?; 32],
        parent_hash: [0; 32],
        header: [0; 80],
        txs: vec![TxFacts {
            txid,
            offset: 81,
            len: 100,
            inputs: Vec::new(),
            outputs: created,
        }],
    })
}

fn writer() -> Result<(tempfile::TempDir, IndexWriter<RocksDbStore>), TestError> {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(RocksDbStore::open(dir.path())?);
    Ok((dir, IndexWriter::open(store, 1)?))
}

#[test]
fn new_unspent_outputs_insert_one_row_each_and_delete_nothing() -> Result<(), TestError> {
    let (_dir, writer) = writer()?;
    let block = coinbase_block(5, 3)?;
    let prepared = writer.prepare_block_from_facts(IndexCapabilities::SCRIPT_LIVE, block)?;
    assert_eq!(
        prepared.row_count,
        1 + 3,
        "one header row plus one insert per new unspent output; no self-deletes"
    );
    Ok(())
}

#[test]
fn tail_rows_count_toward_the_batch_byte_limit() -> Result<(), TestError> {
    let (_dir, writer) = writer()?;
    let caps = IndexCapabilities::HISTORICAL;
    let first = writer.prepare_block_from_facts(caps, coinbase_block(5, 2)?)?;
    let second = writer.prepare_block_from_facts(caps, coinbase_block(6, 2)?)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: usize::MAX,
        max_bytes: 2 * HEADER_ROW_SIZE,
    });
    assert!(
        batch.try_push(first).is_ok(),
        "the first block is always admitted"
    );
    assert!(
        batch.is_full(),
        "one block's tail rows plus its header reach the two-header byte limit"
    );
    assert!(
        batch.try_push(second).is_err(),
        "a full batch refuses the next block"
    );
    Ok(())
}

#[test]
fn live_reader_distinguishes_full_hashes_with_the_same_scan_prefix() -> Result<(), TestError> {
    use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid};
    use bitcoin_rs_index::{IndexWatermark, ScriptHash, ScriptLiveCoin, ScriptLiveRow};

    let (_dir, writer) = writer()?;
    let first = ScriptHash::from_byte_array([0x11; 32]);
    let mut colliding = [0x11; 32];
    colliding[31] = 0x22;
    let second = ScriptHash::from_byte_array(colliding);
    let a = OutPoint::new(Txid(Hash256::from_le_bytes(&[1; 32])), 0);
    let b = OutPoint::new(Txid(Hash256::from_le_bytes(&[2; 32])), 0);
    let mut rows = Vec::new();
    for (hash, outpoint) in [(first, a), (second, b)] {
        let mut row = ScriptLiveRow::new(hash, &outpoint).as_bytes().to_vec();
        row.extend_from_slice(&ScriptLiveCoin::new(hash, 100, 0, false).encode_value()?);
        rows.push(row);
    }
    writer.stage_script_live_rows(&mut rows.into_iter())?;
    writer.publish_script_live_seed(IndexWatermark {
        height: 0,
        hash: [0; 32],
    })?;
    assert_eq!(writer.indexer().iter_live_outpoints(first)?, vec![a]);
    assert_eq!(writer.indexer().iter_live_outpoints(second)?, vec![b]);
    Ok(())
}
