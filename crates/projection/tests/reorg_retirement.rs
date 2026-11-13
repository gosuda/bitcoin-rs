use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid};
use bitcoin_rs_projection::IndexCapability;
use bitcoin_rs_projection::segment::bulk_builder::BulkSegmentBuilder;
use bitcoin_rs_projection::segment::{
    Coverage, IndexGeneration, meta_gen_key, publish_sealed, retire_generation, sealed_gen_key,
};
use bitcoin_rs_projection::types::{ScriptHash, ScriptHistoryOccurrence, TxPositionValue};
use bitcoin_rs_projection::{IndexCapabilities, IndexReader, Indexer};
use bitcoin_rs_storage::budget::UnboundedBudget;
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, SpentPrevout, TxFacts};
use bitcoin_rs_storage::{Bytes, ColumnFamily, KvStore, PrefixScanLimit, RocksDbStore};
use std::sync::Arc;
use tempfile::tempdir;

use crate::support::TestError;

const SCAN_ALL: PrefixScanLimit = PrefixScanLimit {
    max_rows: 100_000,
    max_bytes: 64 << 20,
};
const ROW_LIMIT: PrefixScanLimit = PrefixScanLimit {
    max_rows: 16,
    max_bytes: 1 << 20,
};
fn count_rows_in_prefix<S: KvStore>(
    store: &S,
    cf: ColumnFamily,
    prefix: &[u8],
) -> Result<usize, TestError> {
    let snapshot = store.snapshot()?;
    let iter = snapshot.iter_prefix(cf, prefix)?;
    let mut rows = 0usize;
    for item in iter {
        let _ = item?;
        rows = rows.saturating_add(1);
    }
    Ok(rows)
}

// REO-04, REO-05
#[test]
fn deep_reorg_retires_one_generation_only() -> Result<(), TestError> {
    let gen_id = 1u64;
    let dir = tempdir()?;
    let scratch = tempdir()?;
    let store = Arc::new(RocksDbStore::open(dir.path())?);

    let script = Bytes::copy_from_slice(b"\x76\xa9\x14retire_script\x88\xac");
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
                script: script.clone(),
            }],
        }],
    };
    let spend_block = CommittedBlock {
        height: 2,
        hash: [0x02; 32],
        parent_hash: [0x01; 32],
        header: [0u8; 80],
        txs: vec![TxFacts {
            txid: [0x22; 32],
            offset: 0,
            len: 120,
            inputs: vec![SpentPrevout {
                txid: [0x11; 32],
                vout: 0,
                value: 50_000,
                script: script.clone(),
                height: 1,
                coinbase: false,
            }],
            outputs: Vec::new(),
        }],
    };

    let tx_count = block.txs.len() + spend_block.txs.len();
    let builder = BulkSegmentBuilder::new(
        Arc::new(UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    );
    let coverage = builder
        .build_and_ingest(store.as_ref(), gen_id, &[block, spend_block])
        .map_err(|e| e.to_string())?;
    publish_sealed(
        store.as_ref(),
        gen_id,
        coverage,
        u32::try_from(tx_count)?,
        IndexCapabilities::HISTORICAL,
    )?;

    let gen_prefix = gen_id.to_be_bytes();
    assert!(count_rows_in_prefix(store.as_ref(), ColumnFamily::TxDir, &gen_prefix)? > 0);
    assert!(count_rows_in_prefix(store.as_ref(), ColumnFamily::ScriptDict, &gen_prefix)? > 0);

    let script_before = store.as_ref().snapshot()?.get(
        ColumnFamily::IdxMeta,
        &meta_gen_key(IndexCapability::ScriptHistory),
    )?;
    retire_generation(store.as_ref(), IndexCapability::TxLookup, gen_id)?;

    let snapshot = store.as_ref().snapshot()?;
    let indexer = Indexer::new(Arc::clone(&store));
    let view = indexer.snapshot()?;
    let script_hash = ScriptHash::from_script_bytes(script.as_ref());

    let history = view.funding_rows(script_hash, SCAN_ALL)?;
    assert!(history.complete, "occurrence scan is complete");
    assert_eq!(
        history.rows.len(),
        2,
        "one height group per fixture block survives TxLookup retirement"
    );
    let mut occurrences = Vec::new();
    for row in &history.rows {
        let decoded = ScriptHistoryOccurrence::decode_all(&row.value)
            .ok_or("script history rows decode into occurrences")?;
        for occurrence in decoded {
            occurrences.push((
                row.row.height(),
                occurrence.txid,
                (occurrence.position.offset(), occurrence.position.byte_len()),
                occurrence.flags,
            ));
        }
    }
    assert_eq!(
        occurrences,
        vec![
            (2, [0x22; 32], (0, 120), ScriptHistoryOccurrence::SPENDING,),
            (1, [0x11; 32], (0, 100), ScriptHistoryOccurrence::FUNDING),
        ],
        "the surviving ScriptHistory coverage still answers the fixture funding (txid ..11 at height 1) and spending (txid ..22 at height 2) occurrences with literal byte positions"
    );

    let funding_txid = Txid::from(Hash256::from_le_bytes(&[0x11; 32]));
    let spender = view.spending_rows(
        &OutPoint {
            txid: funding_txid,
            vout: 0,
        },
        ROW_LIMIT,
    )?;
    assert!(spender.complete, "spender scan is complete");
    assert_eq!(
        spender.rows.len(),
        1,
        "the fixture output names exactly one spender"
    );
    assert_eq!(
        spender.rows[0].row.height(),
        2,
        "the fixture spender confirms at height 2"
    );
    assert_eq!(
        TxPositionValue::decode(&spender.rows[0].value).map(|positions| positions
            .iter()
            .map(|position| (position.offset(), position.byte_len()))
            .collect::<Vec<_>>()),
        Some(vec![(0, 120)]),
        "the surviving ScriptHistory coverage still resolves the fixture spender to the ordinal-1 transaction at byte range 0..120"
    );

    assert!(count_rows_in_prefix(store.as_ref(), ColumnFamily::ScriptDict, &gen_prefix)? > 0);
    assert!(count_rows_in_prefix(store.as_ref(), ColumnFamily::ScriptPost, &gen_prefix)? > 0);
    assert!(count_rows_in_prefix(store.as_ref(), ColumnFamily::ScriptStats, &gen_prefix)? > 0);
    assert!(
        count_rows_in_prefix(store.as_ref(), ColumnFamily::TxDir, &gen_prefix)? > 0,
        "retiring TxLookup alone keeps the directory ScriptHistory still publishes"
    );

    let tx_meta = snapshot.get(
        ColumnFamily::IdxMeta,
        &meta_gen_key(IndexCapability::TxLookup),
    )?;
    assert!(
        snapshot
            .get(
                ColumnFamily::IdxMeta,
                &sealed_gen_key(IndexCapability::TxLookup, gen_id),
            )?
            .is_none(),
        "the retired TxLookup sealed record must be deleted"
    );
    let tx_desc = tx_meta
        .as_deref()
        .and_then(IndexGeneration::decode_meta_value);
    assert_eq!(
        tx_desc.map(|desc| desc.gen_id),
        Some(0),
        "retirement rewrites the TxLookup descriptor to the tail-only bounds (no sealed generation)"
    );

    let script_meta = snapshot.get(
        ColumnFamily::IdxMeta,
        &meta_gen_key(IndexCapability::ScriptHistory),
    )?;
    assert_eq!(
        script_meta, script_before,
        "retirement must not rewrite the unaffected ScriptHistory descriptor"
    );
    assert!(script_meta.is_some());
    let script_sealed = snapshot.get(
        ColumnFamily::IdxMeta,
        &sealed_gen_key(IndexCapability::ScriptHistory, gen_id),
    )?;
    assert_eq!(
        script_sealed.as_deref().and_then(Coverage::from_bytes),
        Some(coverage),
        "retirement keeps the ScriptHistory sealed generation"
    );

    retire_generation(store.as_ref(), IndexCapability::ScriptHistory, gen_id)?;

    let snapshot = store.as_ref().snapshot()?;
    for family in [
        ColumnFamily::TxDir,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::ScriptStats,
    ] {
        assert_eq!(
            count_rows_in_prefix(store.as_ref(), family, &gen_prefix)?,
            0,
            "retiring the last owner of {family:?} reclaims the generation's rows"
        );
    }
    let view = indexer.snapshot()?;
    assert!(
        view.funding_rows(script_hash, SCAN_ALL)?.rows.is_empty(),
        "the retired ScriptHistory capability answers no history after the last-owner retirement"
    );
    let script_meta = snapshot.get(
        ColumnFamily::IdxMeta,
        &meta_gen_key(IndexCapability::ScriptHistory),
    )?;
    assert_eq!(
        script_meta
            .as_deref()
            .and_then(IndexGeneration::decode_meta_value)
            .map(|desc| desc.gen_id),
        Some(0),
        "retirement rewrites the ScriptHistory descriptor to the tail-only bounds (no sealed generation)"
    );
    assert!(
        snapshot
            .get(
                ColumnFamily::IdxMeta,
                &sealed_gen_key(IndexCapability::ScriptHistory, gen_id),
            )?
            .is_none(),
        "the last-owner retired ScriptHistory sealed record must be deleted"
    );
    Ok(())
}
