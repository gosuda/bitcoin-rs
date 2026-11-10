use bitcoin_rs_projection::segment::bulk_builder::BulkSegmentBuilder;
use bitcoin_rs_projection::{IndexReader, Indexer, ScriptHash};
use bitcoin_rs_storage::budget::UnboundedBudget;
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, TxFacts};
use bitcoin_rs_storage::{Bytes, PrefixScanLimit, RocksDbStore};
use std::sync::Arc;
use tempfile::tempdir;

use crate::support::TestError;

// PRJ-07
#[test]
fn no_segment_offset_in_answers() -> Result<(), TestError> {
    use bitcoin_rs_projection::types::ScriptHistoryOccurrence;

    let gen_id = 1u64;
    let dir = tempdir()?;
    let scratch = tempdir()?;
    let store = RocksDbStore::open(dir.path())?;

    let block_hash = [0x55u8; 32];
    let txid = [0x42u8; 32];
    let height = 100u32;
    let script = Bytes::copy_from_slice(b"\x76\xa9\x14query_ans_script\x88\xac");

    let block = CommittedBlock {
        height,
        hash: block_hash,
        parent_hash: [0u8; 32],
        header: [0u8; 80],
        txs: vec![TxFacts {
            txid,
            offset: 450,
            len: 220,
            inputs: Vec::new(),
            outputs: vec![CreatedOutput {
                vout: 0,
                value: 50_000,
                script: script.clone(),
            }],
        }],
    };

    let builder = BulkSegmentBuilder::new(
        Arc::new(UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    );
    let coverage = builder
        .build_and_ingest(&store, gen_id, &[block])
        .map_err(|e| e.to_string())?;
    bitcoin_rs_projection::segment::publish_bulk_generation(
        &store,
        gen_id,
        coverage,
        1,
        bitcoin_rs_projection::IndexCapabilities::ALL,
    )?;

    let scripthash = ScriptHash::from_script_bytes(script.as_ref());
    let store = Arc::new(store);
    let indexer = Indexer::new(Arc::clone(&store));
    let view = indexer.snapshot()?;
    let limit = PrefixScanLimit {
        max_rows: 100,
        max_bytes: usize::MAX,
    };
    let funding = view.funding_rows(scripthash, limit)?;
    assert_eq!(funding.rows.len(), 1, "one funding row answers the script");
    assert_eq!(funding.rows[0].row.height(), 100);
    assert_eq!(
        funding.rows[0].row.prefix,
        scripthash.prefix(),
        "the answer key is the logical script prefix and height"
    );
    let occurrences = ScriptHistoryOccurrence::decode_all(&funding.rows[0].value)
        .ok_or("decode funding answer")?;
    assert_eq!(occurrences.len(), 1);
    assert_eq!(
        occurrences[0].txid, txid,
        "the answer names the logical txid"
    );
    assert_eq!(
        occurrences[0].flags,
        ScriptHistoryOccurrence::FUNDING,
        "the answer flags the funding occurrence"
    );
    for row in &funding.rows {
        assert_eq!(row.row.height(), height);
    }
    Ok(())
}
