use bitcoin_rs_projection::IndexCapability;
use bitcoin_rs_projection::segment::bulk_builder::BulkSegmentBuilder;
use bitcoin_rs_projection::segment::{
    GenerationDescriptor, IndexGeneration, TailDescriptor, meta_gen_key, retire_generation,
};
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, TxFacts};
use bitcoin_rs_storage::{Bytes, ColumnFamily, KvStore, RocksDbStore};
use tempfile::tempdir;

use crate::support::TestError;
fn count_rows_in_prefix<S: KvStore>(store: &S, cf: ColumnFamily, prefix: &[u8]) -> usize {
    let Ok(snapshot) = store.snapshot() else {
        return 0;
    };
    let Ok(iter) = snapshot.iter_prefix(cf, prefix) else {
        return 0;
    };
    iter.count()
}

// REO-04, REO-05
#[test]
fn deep_reorg_retires_one_generation_only() -> Result<(), TestError> {
    let gen_id = 1u64;
    let dir = tempdir()?;
    let scratch = tempdir()?;
    let store = RocksDbStore::open(dir.path())?;

    let block = CommittedBlock {
        height: 1,
        hash: [0x01; 32],
        parent_hash: [0u8; 32],
        header: [0u8; 80],
        txs: vec![TxFacts {
            txid: [0x11; 32],
            offset: 0,
            len: 100,
            inputs: Vec::new(),
            outputs: vec![CreatedOutput {
                vout: 0,
                value: 50_000,
                script: Bytes::copy_from_slice(b"\x76\xa9\x14retire_script\x88\xac"),
            }],
        }],
    };

    let builder = BulkSegmentBuilder::new(64 * 1024 * 1024, scratch.path().to_path_buf());
    let coverage = builder
        .build_and_ingest(&store, gen_id, &[block])
        .map_err(|e| e.to_string())?;
    let desc = GenerationDescriptor {
        gen_id,
        coverage,
        tail: TailDescriptor {
            tail_lo: 2,
            tail_hi: 1,
            tail_hash: [0x01; 32],
        },
    };

    let mut batch = store.new_batch();
    batch.put(
        ColumnFamily::IdxMeta,
        &meta_gen_key(IndexCapability::TxLookup),
        &IndexGeneration::encode_meta_value(&desc),
    );
    batch.put(
        ColumnFamily::IdxMeta,
        &meta_gen_key(IndexCapability::ScriptHistory),
        &IndexGeneration::encode_meta_value(&desc),
    );
    store.write_durable(batch)?;

    let gen_prefix = gen_id.to_be_bytes();
    assert!(count_rows_in_prefix(&store, ColumnFamily::TxDir, &gen_prefix) > 0);
    assert!(count_rows_in_prefix(&store, ColumnFamily::ScriptDict, &gen_prefix) > 0);

    retire_generation(&store, IndexCapability::TxLookup, gen_id)?;

    assert_eq!(
        count_rows_in_prefix(&store, ColumnFamily::TxDir, &gen_prefix),
        0
    );

    assert!(count_rows_in_prefix(&store, ColumnFamily::ScriptDict, &gen_prefix) > 0);
    assert!(count_rows_in_prefix(&store, ColumnFamily::ScriptPost, &gen_prefix) > 0);
    assert!(count_rows_in_prefix(&store, ColumnFamily::ScriptStats, &gen_prefix) > 0);

    let snapshot = store.snapshot()?;
    let tx_meta = snapshot.get(
        ColumnFamily::IdxMeta,
        &meta_gen_key(IndexCapability::TxLookup),
    )?;
    assert!(tx_meta.is_none());

    let script_meta = snapshot.get(
        ColumnFamily::IdxMeta,
        &meta_gen_key(IndexCapability::ScriptHistory),
    )?;
    assert!(script_meta.is_some());
    Ok(())
}
