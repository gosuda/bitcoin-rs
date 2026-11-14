//! The live commit path builds each block's compact filter exactly once: the
//! prepare step builds it, and the tail append consumes the prepared copy.

use std::sync::Arc;

use bitcoin_rs_storage::{Bytes, CommittedBlock, CreatedOutput, RocksDbStore, TxFacts};

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
                script: Bytes::copy_from_slice(&[0x51]),
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
