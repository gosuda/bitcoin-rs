use bitcoin_rs_projection::IndexCapability;
use bitcoin_rs_projection::segment::bulk_builder::BulkSegmentBuilder;
use bitcoin_rs_projection::segment::{
    Coverage, RetireFault, SealFault, TailWriterState, append_tail_block, arm_retire_fault,
    arm_seal_fault, meta_gen_key, recover_segments, seal_tail_generation,
};
use bitcoin_rs_storage::budget::UnboundedBudget;
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, SpentPrevout, TxFacts};
use bitcoin_rs_storage::{Bytes, ColumnFamily, KvStore, RocksDbStore};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tempfile::{TempDir, tempdir};

use crate::support::TestError;

fn one_spend_generation() -> Vec<CommittedBlock> {
    vec![CommittedBlock {
        height: 1,
        hash: [0x81; 32],
        parent_hash: [0u8; 32],
        header: [0u8; 80],
        txs: vec![
            TxFacts {
                txid: [0xE1; 32],
                offset: 0,
                len: 100,
                inputs: vec![],
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: 5_000,
                    script: Bytes::copy_from_slice(b"\x51recovery_script\x88\xac"),
                }],
            },
            TxFacts {
                txid: [0xE2; 32],
                offset: 100,
                len: 120,
                inputs: vec![SpentPrevout {
                    txid: [0xE1; 32],
                    vout: 0,
                    value: 4_000,
                    script: Bytes::copy_from_slice(b"\x51recovery_script\x88\xac"),
                    height: 1,
                    coinbase: false,
                }],
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: 3_000,
                    script: Bytes::copy_from_slice(b"\x76\xa9\x14recovery_second\x88\xac"),
                }],
            },
        ],
    }]
}

fn hash_family<S: KvStore>(
    store: &S,
    cf: ColumnFamily,
    gen_id: u64,
) -> Result<[u8; 32], TestError> {
    let snapshot = store.snapshot()?;
    let start = gen_id.to_be_bytes();
    let mut hasher = Sha256::new();
    for item in snapshot.iter_prefix(cf, &start)? {
        let (key, value) = item?;
        hasher.update(u32::try_from(key.len()).unwrap_or(u32::MAX).to_le_bytes());
        hasher.update(&key);
        hasher.update(u32::try_from(value.len()).unwrap_or(u32::MAX).to_le_bytes());
        hasher.update(&value);
    }
    Ok(hasher.finalize().into())
}

fn family_rows(store: &RocksDbStore, cf: ColumnFamily, prefix: &[u8]) -> Result<usize, TestError> {
    let snapshot = store.snapshot()?;
    Ok(snapshot.iter_prefix(cf, prefix)?.count())
}

fn bulk_digests(blocks: &[CommittedBlock]) -> Result<Vec<(ColumnFamily, [u8; 32])>, TestError> {
    let dir = tempdir()?;
    let scratch = tempdir()?;
    let store = RocksDbStore::open(dir.path())?;
    let builder = BulkSegmentBuilder::new(
        Arc::new(UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    );
    builder
        .build_and_ingest(&store, 1, blocks)
        .map_err(|e| e.to_string())?;
    let cfs = [
        ColumnFamily::TxDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
    ];
    cfs.iter()
        .map(|&cf| hash_family(&store, cf, 1).map(|digest| (cf, digest)))
        .collect()
}

fn tail_only_store(blocks: &[CommittedBlock]) -> Result<(TempDir, RocksDbStore), TestError> {
    let dir = tempdir()?;
    let store = RocksDbStore::open(dir.path())?;
    let mut state = TailWriterState::new();
    for block in blocks {
        let mut batch = store.new_batch();
        append_tail_block(&mut batch, block, &mut state);
        store.write_durable(batch)?;
    }
    Ok((dir, store))
}

fn tail_prefix() -> Vec<u8> {
    0u64.to_be_bytes().to_vec()
}

fn gen_prefix() -> Vec<u8> {
    1u64.to_be_bytes().to_vec()
}

const SEGMENT_CFS: [ColumnFamily; 6] = [
    ColumnFamily::TxDir,
    ColumnFamily::ScriptDict,
    ColumnFamily::ScriptPost,
    ColumnFamily::SpendDir,
    ColumnFamily::ScriptStats,
    ColumnFamily::Filters,
];

// PRJ-05
#[test]
fn seal_fault_before_marker_commit_recovers_by_rollback() -> Result<(), TestError> {
    let blocks = one_spend_generation();
    let (_dir, store) = tail_only_store(&blocks)?;
    arm_seal_fault(Some(SealFault::AfterStaging));
    let sealed = seal_tail_generation(
        &store,
        1,
        Coverage::new(1, 1, [0x81; 32]),
        tempdir()?.path(),
    );
    arm_seal_fault(None);
    assert!(sealed.is_err(), "injected fault must abort the seal");

    recover_segments(&store)?;

    for cf in SEGMENT_CFS {
        assert_eq!(
            family_rows(&store, cf, &gen_prefix())?,
            0,
            "{cf:?} gen rows must roll back"
        );
        assert!(
            family_rows(&store, cf, &tail_prefix())? > 0,
            "{cf:?} tail rows must survive the rollback"
        );
    }

    let coverage = Coverage::new(1, 1, [0x81; 32]);
    seal_tail_generation(&store, 1, coverage, tempdir()?.path())?;
    let expected = bulk_digests(&blocks)?;
    for (cf, digest) in expected {
        assert_eq!(hash_family(&store, cf, 1)?, digest, "{cf:?} after re-seal");
    }
    Ok(())
}

// PRJ-05
#[test]
fn seal_fault_after_committed_marker_recovers_by_completion() -> Result<(), TestError> {
    let blocks = one_spend_generation();
    let (_dir, store) = tail_only_store(&blocks)?;
    arm_seal_fault(Some(SealFault::AfterCommitted));
    let sealed = seal_tail_generation(
        &store,
        1,
        Coverage::new(1, 1, [0x81; 32]),
        tempdir()?.path(),
    );
    arm_seal_fault(None);
    assert!(sealed.is_err(), "injected fault must abort the seal");

    recover_segments(&store)?;

    for cf in SEGMENT_CFS {
        assert_eq!(
            family_rows(&store, cf, &tail_prefix())?,
            0,
            "{cf:?} tail must clear"
        );
    }
    let expected = bulk_digests(&blocks)?;
    for (cf, digest) in expected {
        assert_eq!(hash_family(&store, cf, 1)?, digest, "{cf:?} after recovery");
    }
    let snapshot = store.snapshot()?;
    assert!(
        snapshot
            .get(ColumnFamily::IdxMeta, b"seal/staging")?
            .is_none()
    );
    assert!(
        snapshot
            .get(ColumnFamily::IdxMeta, b"seal/committed")?
            .is_none()
    );
    for capability in IndexCapability::ALL {
        assert!(
            snapshot
                .get(ColumnFamily::IdxMeta, &meta_gen_key(capability))?
                .is_some(),
            "{capability:?} descriptor must publish"
        );
    }
    Ok(())
}

// PRJ-05
#[test]
fn seal_fault_after_tail_clear_recovers_by_completion() -> Result<(), TestError> {
    let blocks = one_spend_generation();
    let (_dir, store) = tail_only_store(&blocks)?;
    arm_seal_fault(Some(SealFault::AfterClear));
    let sealed = seal_tail_generation(
        &store,
        1,
        Coverage::new(1, 1, [0x81; 32]),
        tempdir()?.path(),
    );
    arm_seal_fault(None);
    assert!(sealed.is_err(), "injected fault must abort the seal");

    recover_segments(&store)?;

    let expected = bulk_digests(&blocks)?;
    for (cf, digest) in expected {
        assert_eq!(hash_family(&store, cf, 1)?, digest, "{cf:?} after recovery");
    }
    let snapshot = store.snapshot()?;
    assert!(
        snapshot
            .get(ColumnFamily::IdxMeta, b"seal/staging")?
            .is_none()
    );
    Ok(())
}

// PRJ-05
#[test]
fn writer_open_completes_an_interrupted_seal() -> Result<(), TestError> {
    use bitcoin_rs_projection::IndexWriter;

    let blocks = one_spend_generation();
    let dir = tempdir()?;
    let store = Arc::new(RocksDbStore::open(dir.path())?);
    let mut state = TailWriterState::new();
    for block in &blocks {
        let mut batch = store.new_batch();
        append_tail_block(&mut batch, block, &mut state);
        store.write_durable(batch)?;
    }
    let mut marker_batch = store.new_batch();
    marker_batch.put(
        ColumnFamily::UtxoMeta,
        bitcoin_rs_projection::types::INDEX_FORMAT_VERSION_KEY,
        &bitcoin_rs_projection::types::INDEX_FORMAT_VERSION_VALUE,
    );
    store.write_durable(marker_batch)?;
    arm_seal_fault(Some(SealFault::AfterCommitted));
    let sealed = seal_tail_generation(
        store.as_ref(),
        1,
        Coverage::new(1, 1, [0x81; 32]),
        tempdir()?.path(),
    );
    arm_seal_fault(None);
    assert!(sealed.is_err(), "injected fault must abort the seal");

    let _writer = IndexWriter::open(Arc::clone(&store), 1)?;

    for cf in SEGMENT_CFS {
        assert_eq!(
            family_rows(&store, cf, &tail_prefix())?,
            0,
            "{cf:?} tail must clear on open"
        );
    }
    let snapshot = store.snapshot()?;
    assert!(
        snapshot
            .get(ColumnFamily::IdxMeta, b"seal/committed")?
            .is_none()
    );
    assert!(
        snapshot
            .get(
                ColumnFamily::IdxMeta,
                &meta_gen_key(IndexCapability::TxLookup)
            )?
            .is_some(),
        "open must publish the sealed generation descriptor"
    );
    Ok(())
}

// REO-04
#[test]
fn retire_fault_after_tombstone_recovers_by_completion() -> Result<(), TestError> {
    let blocks = one_spend_generation();
    let dir = tempdir()?;
    let scratch = tempdir()?;
    let store = RocksDbStore::open(dir.path())?;
    let builder = BulkSegmentBuilder::new(
        Arc::new(UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    );
    let coverage = builder
        .build_and_ingest(&store, 1, &blocks)
        .map_err(|e| e.to_string())?;
    seal_tail_generation(&store, 1, coverage, tempdir()?.path())?;

    arm_retire_fault(Some(RetireFault::AfterTombstone));
    let retired =
        bitcoin_rs_projection::segment::retire_generation(&store, IndexCapability::TxLookup, 1);
    arm_retire_fault(None);
    assert!(retired.is_err(), "injected fault must abort the retire");

    recover_segments(&store)?;

    assert_eq!(
        family_rows(&store, ColumnFamily::TxDir, &gen_prefix())?,
        0,
        "retired TxDir gen rows must clear"
    );
    for cf in [
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
    ] {
        assert!(
            family_rows(&store, cf, &gen_prefix())? > 0,
            "{cf:?} rows of unaffected capabilities must remain (REO-05)"
        );
    }
    let snapshot = store.snapshot()?;
    assert!(
        snapshot
            .get(
                ColumnFamily::IdxMeta,
                &meta_gen_key(IndexCapability::TxLookup)
            )?
            .is_none(),
        "retired descriptor must clear"
    );
    assert!(
        snapshot
            .get(
                ColumnFamily::IdxMeta,
                &meta_gen_key(IndexCapability::ScriptHistory)
            )?
            .is_some(),
        "unaffected descriptor must remain"
    );
    let tombstones = snapshot
        .scan_prefix_bounded(
            ColumnFamily::IdxMeta,
            b"retire/",
            bitcoin_rs_storage::PrefixScanLimit {
                max_rows: 10,
                max_bytes: usize::MAX,
            },
        )?
        .rows;
    assert!(tombstones.is_empty(), "tombstone must clear after recovery");
    Ok(())
}
