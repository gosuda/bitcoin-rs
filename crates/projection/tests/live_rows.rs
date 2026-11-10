//! Committed-facts rows and the batch byte limit: `PRJ-05`.

use std::sync::Arc;

use bitcoin_rs_projection::{
    HEADER_ROW_SIZE, IndexCapabilities, IndexWriter, PreparedBatch, PreparedBatchLimits,
};
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, TxFacts};
use bitcoin_rs_storage::{Bytes, RocksDbStore};

fn coinbase_block(height: u32, outputs: u32) -> Result<CommittedBlock, Box<dyn std::error::Error>> {
    let mut created = Vec::new();
    for vout in 0..outputs {
        created.push(CreatedOutput {
            vout,
            value: 1_000 + u64::from(vout),
            script: Bytes::from(vec![0x51, u8::try_from(vout)?]),
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

fn writer() -> Result<(tempfile::TempDir, IndexWriter<RocksDbStore>), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(RocksDbStore::open(dir.path())?);
    Ok((dir, IndexWriter::open(store, 1)?))
}

#[test]
fn new_unspent_outputs_insert_one_row_each_and_delete_nothing()
-> Result<(), Box<dyn std::error::Error>> {
    let (_dir, writer) = writer()?;
    let block = coinbase_block(5, 3)?;
    let prepared =
        writer.prepare_block_from_facts(IndexCapabilities::SCRIPT_LIVE, block.clone())?;
    assert_eq!(
        prepared.row_count,
        1 + 3,
        "one header row plus one insert per new unspent output; no self-deletes"
    );
    Ok(())
}

#[test]
fn tail_rows_count_toward_the_batch_byte_limit() -> Result<(), Box<dyn std::error::Error>> {
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
