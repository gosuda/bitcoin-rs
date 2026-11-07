use bitcoin_rs_projection::segment::bulk_builder::BulkSegmentBuilder;
use bitcoin_rs_projection::segment::format::{decode_tx_dir_value, encode_tx_dir_key};
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, TxFacts};
use bitcoin_rs_storage::{Bytes, ColumnFamily, KvStore, RocksDbStore};
use tempfile::tempdir;

use crate::support::TestError;

// PRJ-07
#[test]
fn no_segment_offset_in_answers() -> Result<(), TestError> {
    let gen_id = 1u64;
    let dir = tempdir()?;
    let scratch = tempdir()?;
    let store = RocksDbStore::open(dir.path())?;

    let block_hash = [0x55u8; 32];
    let txid = [0x42u8; 32];
    let height = 100u32;
    let offset = 450u32;
    let len = 220u32;

    let block = CommittedBlock {
        height,
        hash: block_hash,
        parent_hash: [0u8; 32],
        header: [0u8; 80],
        txs: vec![TxFacts {
            txid,
            offset,
            len,
            inputs: Vec::new(),
            outputs: vec![CreatedOutput {
                vout: 0,
                value: 50_000,
                script: Bytes::copy_from_slice(b"\x76\xa9\x14query_ans_script\x88\xac"),
            }],
        }],
    };

    let builder = BulkSegmentBuilder::new(64 * 1024 * 1024, scratch.path().to_path_buf());
    builder
        .build_and_ingest(&store, gen_id, &[block])
        .map_err(|e| e.to_string())?;

    let key = encode_tx_dir_key(gen_id, &txid, height);
    let snapshot = store.snapshot()?;
    let raw_val = snapshot
        .get(ColumnFamily::TxDir, &key)?
        .ok_or("found tx_dir")?;

    let (found_hash, ordinal, found_offset, found_len) =
        decode_tx_dir_value(&raw_val).ok_or("decode tx_dir")?;
    assert_eq!(found_hash, block_hash);
    assert_eq!(ordinal, 0);
    assert_eq!(found_offset, offset);
    assert_eq!(found_len, len);

    let logical_height = height;
    let logical_hash = found_hash;
    let logical_ordinal = ordinal;

    assert_eq!(logical_height, 100);
    assert_eq!(logical_hash, [0x55u8; 32]);
    assert_eq!(logical_ordinal, 0);
    Ok(())
}
