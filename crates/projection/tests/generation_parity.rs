use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid};
use bitcoin_rs_projection::segment::bulk_builder::{BulkSegmentBuilder, StreamingSegmentBuilder};
use bitcoin_rs_projection::segment::{
    Coverage, NoSealedTxOrdinals, TailWriterState, append_tail_block, meta_gen_key,
    seal_tail_generation, sealed_generations,
};
use bitcoin_rs_projection::{
    IndexCapabilities, IndexCapability, IndexError, IndexReader, IndexWatermark, IndexWriter,
    Indexer, PreparedBatch, PreparedBatchLimits, ScriptHash, ScriptHistoryOccurrence,
    TxIndexScanRow, TxIndexSnapshot,
};
use bitcoin_rs_storage::budget::{BudgetCharge, BudgetError, BudgetOwner, UnboundedBudget};
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, SpentPrevout, TxFacts};
use bitcoin_rs_storage::{
    Bytes, ColumnFamily, KvStore, PrefixScanLimit, RocksDbStore, StorageError,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tempfile::tempdir;

use crate::support::TestError;
fn cross_block_script(height: u32) -> Bytes {
    let mut script = b"\x76\xa9\x14cross_block_spent_\x88\xac".to_vec();
    script[15] = u8::try_from(height & 0xff).unwrap_or(0);
    Bytes::from(script)
}

fn self_transfer_script(height: u32) -> Bytes {
    let mut script = b"\x76\xa9\x14self_transfer_script\x88\xac".to_vec();
    script[16] = u8::try_from(height & 0xff).unwrap_or(0);
    Bytes::from(script)
}

fn cross_block_input(height: u32) -> SpentPrevout {
    let (txid, spent_height, script) = if height > 1 {
        let mut txid = [0u8; 32];
        txid[..4].copy_from_slice(&(height - 1).to_be_bytes());
        txid[4..8].copy_from_slice(&4u32.to_be_bytes());
        (txid, height - 1, cross_block_script(height - 1))
    } else {
        ([0xFFu8; 32], 0, cross_block_script(0))
    };
    SpentPrevout {
        txid,
        vout: 0,
        value: 33_000,
        script,
        height: spent_height,
        coinbase: false,
    }
}

fn cross_block_second_input(height: u32) -> SpentPrevout {
    let mut second = cross_block_input(height);
    second.vout = 1;
    second.value = 7_000;
    second
}

fn create_synthetic_blocks(count: u32) -> Vec<CommittedBlock> {
    let Ok(capacity) = usize::try_from(count) else {
        return Vec::new();
    };
    let mut blocks = Vec::with_capacity(capacity);
    for h in 1..=count {
        let mut hash = [0u8; 32];
        hash[..4].copy_from_slice(&h.to_be_bytes());
        hash[31] = 0xAA;

        let mut txs = Vec::new();
        for t in 0..5u32 {
            let mut txid = [0u8; 32];
            txid[..4].copy_from_slice(&h.to_be_bytes());
            txid[4..8].copy_from_slice(&t.to_be_bytes());

            let mut inputs = Vec::new();
            if t > 0 && t != 2 {
                let mut prev_txid = [0u8; 32];
                prev_txid[..4].copy_from_slice(&h.to_be_bytes());
                prev_txid[4..8].copy_from_slice(&(t.saturating_sub(1)).to_be_bytes());
                inputs.push(SpentPrevout {
                    txid: prev_txid,
                    vout: 0,
                    value: 50_000,
                    script: Bytes::copy_from_slice(b"\x76\xa9\x14synthetic_prev_script\x88\xac"),
                    height: 0,
                    coinbase: false,
                });
            }
            if t == 2 {
                inputs.push(cross_block_input(h));
                inputs.push(cross_block_second_input(h));
            }
            if t == 4 {
                let mut older_txid = [0u8; 32];
                older_txid[0] = 0xCC;
                inputs.push(SpentPrevout {
                    txid: older_txid,
                    vout: 0,
                    value: 21_000,
                    script: self_transfer_script(h),
                    height: 0,
                    coinbase: false,
                });
            }

            let outputs = vec![
                CreatedOutput {
                    vout: 0,
                    value: if t == 4 { 20_000 } else { 50_000 },
                    script: if t == 4 {
                        self_transfer_script(h)
                    } else {
                        Bytes::copy_from_slice(b"\x76\xa9\x14synthetic_output_script\x88\xac")
                    },
                },
                CreatedOutput {
                    vout: 1,
                    value: 25_000,
                    script: Bytes::copy_from_slice(b"\x00\x14synthetic_witness_script"),
                },
            ];

            txs.push(TxFacts {
                txid,
                offset: t.saturating_mul(100),
                len: 90,
                inputs,
                outputs,
            });
        }

        blocks.push(CommittedBlock {
            height: h,
            hash,
            parent_hash: [0u8; 32],
            header: [0u8; 80],
            txs,
        });
    }
    blocks
}

fn hash_cf_entry(hasher: &mut Sha256, k: &[u8], v: &[u8]) -> Result<(), TestError> {
    let k_len = u32::try_from(k.len())?;
    let v_len = u32::try_from(v.len())?;
    hasher.update(k_len.to_le_bytes());
    hasher.update(k);
    hasher.update(v_len.to_le_bytes());
    hasher.update(v);
    Ok(())
}

fn compute_family_digest<S: KvStore>(
    store: &S,
    cf: ColumnFamily,
    gen_id: u64,
) -> Result<([u8; 32], u64), TestError> {
    let start = gen_id.to_be_bytes();
    let end = gen_id.saturating_add(1).to_be_bytes();
    let mut hasher = Sha256::new();
    let snapshot = store.snapshot()?;
    let mut rows = 0u64;
    let iter = snapshot.iter_prefix(cf, &start)?;
    for item in iter {
        let (k, v) = item?;
        if k.as_slice() >= end.as_slice() {
            break;
        }
        hash_cf_entry(&mut hasher, &k, &v)?;
        rows = rows.saturating_add(1);
    }
    Ok((hasher.finalize().into(), rows))
}

// PRJ-09
#[test]
fn bulk_and_live_generations_are_byte_identical() -> Result<(), TestError> {
    let blocks = create_synthetic_blocks(50);
    let gen_id = 1u64;
    let dir_b = tempdir()?;
    let scratch_b = tempdir()?;
    let store_b = RocksDbStore::open(dir_b.path())?;
    let builder_b = BulkSegmentBuilder::new(
        Arc::new(UnboundedBudget),
        None,
        scratch_b.path().to_path_buf(),
    );
    let coverage = builder_b
        .build_and_ingest(&store_b, gen_id, &blocks)
        .map_err(|e| e.to_string())?;

    let dir_a = tempdir()?;
    let scratch_a = tempdir()?;
    let store_a = RocksDbStore::open(dir_a.path())?;

    let mut tail_state = TailWriterState::new();
    for block in &blocks {
        let mut batch = store_a.new_batch();
        append_tail_block(&mut batch, block, &mut tail_state, &NoSealedTxOrdinals)?;
        store_a.write_durable(batch)?;
    }

    seal_tail_generation(
        &store_a,
        gen_id,
        coverage.last_height,
        IndexCapabilities::ALL,
        scratch_a.path(),
    )?;

    let indexed_cfs = [
        ColumnFamily::TxDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
    ];

    for &cf in &indexed_cfs {
        let (digest_a, rows_a) = compute_family_digest(&store_a, cf, gen_id)?;
        let (digest_b, rows_b) = compute_family_digest(&store_b, cf, gen_id)?;
        assert!(rows_a > 0, "{cf:?} has no sealed rows in the tail build");
        assert_eq!(
            rows_a, rows_b,
            "{cf:?} row count differs between tail and bulk"
        );
        assert_eq!(digest_a, digest_b, "mismatch on {:?}", cf);
    }
    Ok(())
}

struct FamilyDigestPair {
    family: ColumnFamily,
    tail: [u8; 32],
    bulk: [u8; 32],
    tail_rows: u64,
    bulk_rows: u64,
}

fn cross_block_spend_generation() -> Vec<CommittedBlock> {
    let funded_script = Bytes::copy_from_slice(b"\x76\xa9\x14fresh_output\x88\xac");
    vec![
        CommittedBlock {
            height: 1,
            hash: [0x71; 32],
            parent_hash: [0u8; 32],
            header: [0u8; 80],
            txs: vec![TxFacts {
                txid: [0xD0; 32],
                offset: 0,
                len: 120,
                inputs: Vec::new(),
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: 20_000,
                    script: funded_script.clone(),
                }],
            }],
        },
        CommittedBlock {
            height: 2,
            hash: [0x72; 32],
            parent_hash: [0x71; 32],
            header: [0u8; 80],
            txs: vec![TxFacts {
                txid: [0xD1; 32],
                offset: 0,
                len: 120,
                inputs: vec![SpentPrevout {
                    txid: [0xD0; 32],
                    vout: 0,
                    value: 20_000,
                    script: funded_script,
                    height: 1,
                    coinbase: false,
                }],
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: 19_000,
                    script: Bytes::copy_from_slice(b"\x76\xa9\x14spent_output\x88\xac"),
                }],
            }],
        },
    ]
}

fn tail_seal_and_bulk_family_digests(
    blocks: &[CommittedBlock],
    gen_id: u64,
) -> Result<Vec<FamilyDigestPair>, TestError> {
    let indexed_cfs = [
        ColumnFamily::TxDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
    ];
    let dir_tail = tempdir()?;
    let scratch_tail = tempdir()?;
    let store_tail = RocksDbStore::open(dir_tail.path())?;
    let mut tail_state = TailWriterState::new();
    for block in blocks {
        let mut batch = store_tail.new_batch();
        append_tail_block(&mut batch, block, &mut tail_state, &NoSealedTxOrdinals)?;
        store_tail.write_durable(batch)?;
    }
    let coverage_tail = Coverage::new(
        blocks.first().map_or(0, |b| b.height),
        blocks.last().map_or(0, |b| b.height),
        blocks.last().map_or([0u8; 32], |b| b.hash),
    );
    seal_tail_generation(
        &store_tail,
        gen_id,
        coverage_tail.last_height,
        IndexCapabilities::ALL,
        scratch_tail.path(),
    )?;

    let dir_bulk = tempdir()?;
    let scratch_bulk = tempdir()?;
    let store_bulk = RocksDbStore::open(dir_bulk.path())?;
    let builder = BulkSegmentBuilder::new(
        Arc::new(UnboundedBudget),
        None,
        scratch_bulk.path().to_path_buf(),
    );
    let coverage_bulk = builder
        .build_and_ingest(&store_bulk, gen_id, blocks)
        .map_err(|e| e.to_string())?;
    assert_eq!(coverage_tail, coverage_bulk);

    let mut pairs = Vec::new();
    for &cf in &indexed_cfs {
        let (tail, tail_rows) = compute_family_digest(&store_tail, cf, gen_id)?;
        let (bulk, bulk_rows) = compute_family_digest(&store_bulk, cf, gen_id)?;
        pairs.push(FamilyDigestPair {
            family: cf,
            tail,
            bulk,
            tail_rows,
            bulk_rows,
        });
    }
    Ok(pairs)
}

// PRJ-09
#[test]
fn cross_block_spends_produce_identical_tail_and_bulk_segments() -> Result<(), TestError> {
    let blocks = cross_block_spend_generation();
    assert_eq!(blocks.len(), 2, "the spend fixture spans two blocks");
    assert_eq!(
        blocks[1].txs[0].inputs[0].txid, blocks[0].txs[0].txid,
        "block 2 spends an output created in block 1"
    );
    let mut spend_rows = 0u64;
    for pair in tail_seal_and_bulk_family_digests(&blocks, 1)? {
        assert!(pair.tail_rows > 0, "{:?} has no sealed rows", pair.family);
        assert_eq!(
            pair.tail_rows, pair.bulk_rows,
            "{:?} row count differs",
            pair.family
        );
        assert_eq!(
            pair.tail, pair.bulk,
            "{:?} diverges on cross-block spend",
            pair.family
        );
        if pair.family == ColumnFamily::SpendDir {
            spend_rows = pair.bulk_rows;
        }
    }
    assert!(spend_rows > 0, "the cross-block spend writes SpendDir rows");
    Ok(())
}

// PRJ-07, PRJ-09
#[test]
fn same_tx_fund_and_spend_keeps_both_posting_occurrences() -> Result<(), TestError> {
    use bitcoin_rs_projection::segment::format::decode_posting_items;
    let script = self_transfer_script(7);
    let blocks = vec![CommittedBlock {
        height: 1,
        hash: [0x72; 32],
        parent_hash: [0u8; 32],
        header: [0u8; 80],
        txs: vec![TxFacts {
            txid: [0xD2; 32],
            offset: 0,
            len: 130,
            inputs: vec![SpentPrevout {
                txid: [0xCC; 32],
                vout: 0,
                value: 21_000,
                script: script.clone(),
                height: 0,
                coinbase: false,
            }],
            outputs: vec![CreatedOutput {
                vout: 0,
                value: 20_000,
                script,
            }],
        }],
    }];

    for pair in tail_seal_and_bulk_family_digests(&blocks, 1)? {
        if pair.family == ColumnFamily::SpendDir {
            assert_eq!(
                pair.tail_rows, 0,
                "input CC names no in-generation creation"
            );
            assert_eq!(
                pair.bulk_rows, 0,
                "input CC names no in-generation creation"
            );
        } else {
            assert!(pair.tail_rows > 0, "{:?} has no sealed rows", pair.family);
        }
        assert_eq!(
            pair.tail, pair.bulk,
            "{:?} diverges on same-tx fund and spend",
            pair.family
        );
        if pair.family == ColumnFamily::ScriptStats {
            assert_ne!(pair.bulk, [0u8; 32], "stats row missing");
        }
    }
    let dir = tempdir()?;
    let scratch = tempdir()?;
    let store = RocksDbStore::open(dir.path())?;
    BulkSegmentBuilder::new(
        Arc::new(UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    )
    .build_and_ingest(&store, 1, &blocks)
    .map_err(|e| e.to_string())?;
    let snapshot = store.snapshot()?;
    let mut postings = 0usize;
    for item in snapshot.iter_prefix(ColumnFamily::ScriptPost, &1u64.to_be_bytes())? {
        let (_, value) = item?;
        postings += decode_posting_items(&value)
            .ok_or("decode posting items")?
            .len();
    }
    assert_eq!(
        postings, 2,
        "one funding and one spending posting share the script"
    );
    {
        use bitcoin_rs_projection::segment::format::{
            decode_tx_dir_key, decode_tx_dir_value, encode_spend_dir_key, encode_tx_dir_key,
        };
        let funded_key = encode_tx_dir_key(1, &[0xD2; 32], 1);
        let funded_value = snapshot
            .get(ColumnFamily::TxDir, &funded_key)?
            .ok_or("funded D2 has a TxDir row at height 1")?;
        let (_, creation, _, _) =
            decode_tx_dir_value(&funded_value).ok_or("decode funded TxDir value")?;
        for item in snapshot.iter_prefix(ColumnFamily::TxDir, &1u64.to_be_bytes())? {
            let (key, _) = item?;
            if let Some((_, txid, _)) = decode_tx_dir_key(&key) {
                assert_ne!(
                    txid, [0xCC; 32],
                    "spent CC has no TxDir creation in generation 1"
                );
            }
        }
        let spend_key = encode_spend_dir_key(1, creation, 0);
        assert!(
            snapshot.get(ColumnFamily::SpendDir, &spend_key)?.is_none(),
            "funded D2 vout 0 has no spender in generation 1"
        );
        let mut spend_rows = 0u64;
        for item in snapshot.iter_prefix(ColumnFamily::SpendDir, &1u64.to_be_bytes())? {
            let _ = item?;
            spend_rows = spend_rows.saturating_add(1);
        }
        assert_eq!(spend_rows, 0, "input CC names no in-generation creation");
    }
    Ok(())
}

type ScriptHistoryPair = (u32, [u8; 32], [u8; 32], u8);

fn script_history_pairs(
    view: &dyn TxIndexSnapshot,
    scripthash: ScriptHash,
) -> Result<Vec<ScriptHistoryPair>, TestError> {
    const SCAN_ALL: PrefixScanLimit = PrefixScanLimit {
        max_rows: 100_000,
        max_bytes: 64 << 20,
    };
    let scan = view.funding_rows(scripthash, SCAN_ALL)?;
    assert!(scan.complete, "the history scan must be complete");
    let mut pairs = Vec::new();
    for row in scan.rows {
        let occurrences = ScriptHistoryOccurrence::decode_all(&row.value)
            .ok_or("history occurrence decode failed")?;
        for occurrence in occurrences {
            pairs.push((
                row.row.height(),
                occurrence.scripthash.to_byte_array(),
                occurrence.txid,
                occurrence.flags,
            ));
        }
    }
    pairs.sort_unstable();
    Ok(pairs)
}

// IDX-09
#[test]
fn empty_script_history_matches_bulk_and_live() -> Result<(), TestError> {
    const FUND_TXID: [u8; 32] = [0xD0; 32];
    const SPEND_TXID: [u8; 32] = [0xD1; 32];
    let blocks = vec![
        CommittedBlock {
            height: 1,
            hash: [0x81; 32],
            parent_hash: [0u8; 32],
            header: [0u8; 80],
            txs: vec![TxFacts {
                txid: FUND_TXID,
                offset: 0,
                len: 120,
                inputs: Vec::new(),
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: 20_000,
                    script: Bytes::new(),
                }],
            }],
        },
        CommittedBlock {
            height: 2,
            hash: [0x82; 32],
            parent_hash: [0x81; 32],
            header: [0u8; 80],
            txs: vec![TxFacts {
                txid: SPEND_TXID,
                offset: 0,
                len: 120,
                inputs: vec![SpentPrevout {
                    txid: FUND_TXID,
                    vout: 0,
                    value: 20_000,
                    script: Bytes::new(),
                    height: 1,
                    coinbase: false,
                }],
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: 19_000,
                    script: Bytes::copy_from_slice(b"\x51"),
                }],
            }],
        },
    ];
    let empty_script_hash = ScriptHash::from_byte_array(Sha256::digest(b"").into());

    let live_pairs = {
        let dir = tempdir()?;
        let scratch = tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let mut tail_state = TailWriterState::new();
        for block in &blocks {
            let mut batch = store.new_batch();
            append_tail_block(&mut batch, block, &mut tail_state, &NoSealedTxOrdinals)?;
            store.write_durable(batch)?;
        }
        seal_tail_generation(store.as_ref(), 1, 2, IndexCapabilities::ALL, scratch.path())?;
        let indexer = Indexer::new(Arc::clone(&store));
        let view = indexer.snapshot()?;
        script_history_pairs(view.as_ref(), empty_script_hash)?
    };

    let bulk_pairs = {
        let dir = tempdir()?;
        let scratch = tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let builder = BulkSegmentBuilder::new(
            Arc::new(UnboundedBudget),
            None,
            scratch.path().to_path_buf(),
        );
        let coverage = builder
            .build_and_ingest(store.as_ref(), 1, &blocks)
            .map_err(|e| e.to_string())?;
        publish_rebuild_index_generation(store.as_ref(), 1, coverage, &blocks)?;
        let indexer = Indexer::new(Arc::clone(&store));
        let view = indexer.snapshot()?;
        script_history_pairs(view.as_ref(), empty_script_hash)?
    };

    let expected = vec![
        (
            1,
            empty_script_hash.to_byte_array(),
            FUND_TXID,
            ScriptHistoryOccurrence::FUNDING,
        ),
        (
            2,
            empty_script_hash.to_byte_array(),
            SPEND_TXID,
            ScriptHistoryOccurrence::SPENDING,
        ),
    ];
    assert_eq!(live_pairs, expected, "live tail empty-script history");
    assert_eq!(bulk_pairs, expected, "bulk empty-script history");
    assert_eq!(live_pairs, bulk_pairs, "bulk and live generations agree");
    Ok(())
}

// PRJ-08
#[test]
fn seal_repack_respects_posting_chunk_byte_cap() -> Result<(), TestError> {
    use bitcoin_rs_projection::segment::format::{decode_posting_items, decode_script_post_key};
    const PRJ_08_CHUNK_MAX_BYTES: usize = 4096;

    fn one_script_block(txs: usize) -> CommittedBlock {
        let txs = (0..txs)
            .map(|index| {
                let mut txid = [0u8; 32];
                txid[..8].copy_from_slice(&u64::try_from(index).unwrap_or(0).to_le_bytes());
                bitcoin_rs_storage::committed_facts::TxFacts {
                    txid,
                    offset: 0,
                    len: 1,
                    inputs: Vec::new(),
                    outputs: vec![CreatedOutput {
                        vout: 0,
                        value: 1,
                        script: Bytes::copy_from_slice(&[0x51]),
                    }],
                }
            })
            .collect();
        CommittedBlock {
            height: 0,
            hash: [0x11; 32],
            parent_hash: [0u8; 32],
            header: [0u8; 80],
            txs,
        }
    }

    let occurrences = 2_049usize;
    let dir = tempdir()?;
    let scratch = tempdir()?;
    let store = std::sync::Arc::new(RocksDbStore::open(dir.path())?);
    let mut writer = bitcoin_rs_projection::IndexWriter::open(std::sync::Arc::clone(&store), 1)?
        .with_seal_scratch(scratch.path().to_path_buf());
    let prepared =
        writer.prepare_block_from_facts(IndexCapabilities::ALL, one_script_block(occurrences))?;
    let mut batch =
        bitcoin_rs_projection::PreparedBatch::new(bitcoin_rs_projection::PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
    batch
        .try_push(prepared)
        .map_err(|_| "block must be contiguous")?;
    writer.commit_forward(batch)?;
    seal_tail_generation(store.as_ref(), 1, 0, IndexCapabilities::ALL, scratch.path())?;

    let snapshot = store.snapshot()?;
    let mut total_items = 0usize;
    let mut chunks = 0usize;
    let start = 1u64.to_be_bytes();
    for item in snapshot.iter_prefix(ColumnFamily::ScriptPost, &start)? {
        let (key, value) = item?;
        let (_, script_id, _) = decode_script_post_key(&key).ok_or("decode post key")?;
        assert_eq!(script_id, 0);
        assert!(
            value.len() <= PRJ_08_CHUNK_MAX_BYTES,
            "sealed chunk is {} bytes, cap is {}",
            value.len(),
            PRJ_08_CHUNK_MAX_BYTES
        );
        chunks += 1;
        total_items += decode_posting_items(&value)
            .ok_or("decode posting items")?
            .len();
    }
    assert!(chunks > 1, "the posting list must split across chunks");
    assert_eq!(
        total_items, occurrences,
        "seal lost or duplicated occurrences"
    );
    Ok(())
}

struct PoolBudget {
    capacity: u64,
    remaining: AtomicU64,
    peak_outstanding: AtomicU64,
}

impl PoolBudget {
    fn new(capacity: u64) -> Self {
        Self {
            capacity,
            remaining: AtomicU64::new(capacity),
            peak_outstanding: AtomicU64::new(0),
        }
    }

    fn peak(&self) -> u64 {
        self.peak_outstanding.load(Ordering::SeqCst)
    }
}

impl BudgetCharge for PoolBudget {
    fn reserve_bytes(&self, _owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
        let mut current = self.remaining.load(Ordering::SeqCst);
        loop {
            if current < bytes {
                return Err(BudgetError::BudgetExhausted);
            }
            match self.remaining.compare_exchange(
                current,
                current - bytes,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    let outstanding = self.capacity - self.remaining.load(Ordering::SeqCst);
                    let peak = self.peak_outstanding.load(Ordering::SeqCst);
                    if outstanding > peak {
                        self.peak_outstanding.store(outstanding, Ordering::SeqCst);
                    }
                    return Ok(());
                }
                Err(actual) => current = actual,
            }
        }
    }

    fn allocate_bytes(&self, _owner: BudgetOwner, _bytes: u64) -> Result<(), BudgetError> {
        Ok(())
    }

    fn release_bytes(&self, _owner: BudgetOwner, bytes: u64) {
        self.remaining.fetch_add(bytes, Ordering::SeqCst);
    }

    fn available_bytes(&self, _owner: BudgetOwner) -> u64 {
        self.remaining.load(Ordering::SeqCst)
    }
}

struct SpillOutcome {
    digests: Vec<(ColumnFamily, ([u8; 32], u64))>,
    spills: usize,
    peak_outstanding: u64,
    leftover_files: usize,
}

// PRJ-09
fn run_stream_build(
    budget: PoolBudget,
    blocks: &[CommittedBlock],
    gen_id: u64,
) -> Result<SpillOutcome, TestError> {
    let pool = Arc::new(budget);
    let dir = tempdir()?;
    let scratch = tempdir()?;
    let store = RocksDbStore::open(dir.path())?;
    let builder = BulkSegmentBuilder::new(pool.clone(), None, scratch.path().to_path_buf());
    let mut stream: StreamingSegmentBuilder = builder.stream(gen_id);
    for block in blocks {
        stream.push_block(block).map_err(|e| e.to_string())?;
    }
    stream.finish(&store).map_err(|e| e.to_string())?;
    let spills = stream.total_runs_spilled();
    let cfs = [
        ColumnFamily::TxDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
    ];
    let mut digests = Vec::new();
    for &cf in &cfs {
        let digest = compute_family_digest(&store, cf, gen_id)?;
        assert!(
            digest.1 > 0,
            "{cf:?} has no sealed rows in the stream build"
        );
        digests.push((cf, digest));
    }

    let leftover_files = std::fs::read_dir(scratch.path())?
        .filter_map(|entry| entry.ok())
        .count();
    Ok(SpillOutcome {
        digests,
        spills,
        peak_outstanding: pool.peak(),
        leftover_files,
    })
}

// PRJ-09
#[test]
fn tiny_budget_spills_sorted_runs_and_matches_unbounded_output() -> Result<(), TestError> {
    let blocks = create_synthetic_blocks(120);
    const POOL: u64 = 48 * 1024;
    let bounded = run_stream_build(PoolBudget::new(POOL), &blocks, 1)?;
    let unbounded = run_stream_build(PoolBudget::new(u64::MAX), &blocks, 1)?;
    assert!(bounded.spills > 0, "tiny budget must spill sorted runs");
    assert!(
        bounded.peak_outstanding <= POOL + 4096,
        "retained {} exceeded pool plus one row",
        bounded.peak_outstanding
    );
    assert_eq!(bounded.digests, unbounded.digests);
    assert_eq!(
        bounded.leftover_files, 0,
        "finish must remove spill runs from scratch"
    );
    Ok(())
}

// PRJ-09
#[test]
fn stream_sweeps_stale_run_files_from_scratch() -> Result<(), TestError> {
    let dir = tempdir()?;
    let scratch = tempdir()?;
    let store = RocksDbStore::open(dir.path())?;
    std::fs::write(scratch.path().join("segbuild-stale000001"), b"junk")?;
    let builder = BulkSegmentBuilder::new(
        Arc::new(UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    );
    let mut stream = builder.stream(1);
    for block in &create_synthetic_blocks(2) {
        stream.push_block(block).map_err(|e| e.to_string())?;
    }
    stream.finish(&store).map_err(|e| e.to_string())?;
    let leftovers = std::fs::read_dir(scratch.path())?
        .filter_map(|entry| entry.ok())
        .count();
    assert_eq!(leftovers, 0, "restart sweep must clear stale run files");
    Ok(())
}

// PRJ-05
#[test]
fn reset_offline_clears_segment_families_and_descriptors() -> Result<(), TestError> {
    use bitcoin_rs_projection::IndexCapability;
    use bitcoin_rs_projection::reset_offline;
    use bitcoin_rs_storage::PrefixScanLimit;

    let blocks = create_synthetic_blocks(3);
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
    assert!(coverage.last_height > 0, "the fixture covers blocks");
    let pre = family_totals(&store)?;
    assert!(
        pre.iter().any(|(_, rows)| *rows > 0),
        "the bulk build writes segment rows before reset"
    );

    let mut batch = store.new_batch();
    batch.put(
        ColumnFamily::IdxMeta,
        &meta_gen_key(IndexCapability::TxLookup),
        &[7u8; 88],
    );
    store.write_durable(batch)?;

    reset_offline(&store)?;

    for cf in [
        ColumnFamily::IdxMeta,
        ColumnFamily::TxDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
    ] {
        let scan = store.scan_prefix_bounded(
            cf,
            &[],
            PrefixScanLimit {
                max_rows: 1,
                max_bytes: usize::MAX,
            },
        )?;
        assert!(
            scan.rows.is_empty(),
            "{cf:?} still has rows after reset_offline"
        );
    }
    Ok(())
}

fn p2wpkh_script(tag: u32) -> Bytes {
    let mut script = vec![0x00u8, 0x14];
    script.extend_from_slice(&tag.to_le_bytes());
    script.extend_from_slice(&[0x11u8; 16]);
    Bytes::from(script)
}

fn p2tr_script(tag: u32) -> Bytes {
    let mut script = vec![0x51u8, 0x20];
    script.extend_from_slice(&tag.to_le_bytes());
    script.extend_from_slice(&[0x22u8; 28]);
    Bytes::from(script)
}

fn same_block_script(tag: u32) -> Bytes {
    let mut script = vec![0x00u8, 0x20];
    script.extend_from_slice(&tag.to_le_bytes());
    script.extend_from_slice(&[0x33u8; 26]);
    Bytes::from(script)
}

fn chain_txid(height: u32, tag: u8) -> [u8; 32] {
    let mut txid = [0u8; 32];
    txid[..4].copy_from_slice(&height.to_be_bytes());
    txid[4] = tag;
    txid[31] = 0xD1;
    txid
}

struct SpendChain {
    blocks: Vec<CommittedBlock>,
    scripts: Vec<Bytes>,
    spent: Vec<([u8; 32], u32)>,
}

fn create_spend_chain(count: u32) -> SpendChain {
    let mut blocks = Vec::new();
    let mut seen = BTreeSet::new();
    let mut scripts = Vec::new();
    let mut spent = Vec::new();
    let mut remember = |script: Bytes| {
        if seen.insert(script.to_vec()) {
            scripts.push(script);
        }
    };
    for height in 1..=count {
        let mut hash = [0u8; 32];
        hash[..4].copy_from_slice(&height.to_be_bytes());
        hash[31] = 0xBB;
        let mut parent_hash = [0u8; 32];
        if height > 1 {
            parent_hash[..4].copy_from_slice(&height.saturating_sub(1).to_be_bytes());
            parent_hash[31] = 0xBB;
        }
        let coinbase_txid = chain_txid(height, 0xC0);
        let fee_scripts = [p2wpkh_script(height), p2tr_script(height)];
        for script in &fee_scripts {
            remember(script.clone());
        }
        let mut txs = vec![TxFacts {
            txid: coinbase_txid,
            offset: 0,
            len: 100,
            inputs: Vec::new(),
            outputs: vec![
                CreatedOutput {
                    vout: 0,
                    value: 50_000,
                    script: fee_scripts[0].clone(),
                },
                CreatedOutput {
                    vout: 1,
                    value: 25_000,
                    script: fee_scripts[1].clone(),
                },
            ],
        }];
        let fund_txid = chain_txid(height, 0xF0);
        let fund_script = same_block_script(height);
        let fund_end = same_block_script(100_000u32.saturating_add(height));
        remember(fund_script.clone());
        remember(fund_end.clone());
        txs.push(TxFacts {
            txid: fund_txid,
            offset: 100,
            len: 90,
            inputs: Vec::new(),
            outputs: vec![CreatedOutput {
                vout: 0,
                value: 10_000,
                script: fund_script.clone(),
            }],
        });
        txs.push(TxFacts {
            txid: chain_txid(height, 0xF1),
            offset: 190,
            len: 110,
            inputs: vec![SpentPrevout {
                txid: fund_txid,
                vout: 0,
                value: 10_000,
                script: fund_script,
                height,
                coinbase: false,
            }],
            outputs: vec![CreatedOutput {
                vout: 0,
                value: 9_000,
                script: fund_end,
            }],
        });
        spent.push((fund_txid, 0));
        if height >= 2 {
            let prev = height.saturating_sub(1);
            let script = p2wpkh_script(prev);
            remember(script.clone());
            let out_script = p2wpkh_script(10_000u32.saturating_add(height));
            remember(out_script.clone());
            txs.push(TxFacts {
                txid: chain_txid(height, 0x51),
                offset: 300,
                len: 120,
                inputs: vec![SpentPrevout {
                    txid: chain_txid(prev, 0xC0),
                    vout: 0,
                    value: 50_000,
                    script,
                    height: prev,
                    coinbase: false,
                }],
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: 49_000,
                    script: out_script,
                }],
            });
            spent.push((chain_txid(prev, 0xC0), 0));
        }
        if height >= 3 {
            let prev = height.saturating_sub(2);
            let script = p2tr_script(prev);
            remember(script.clone());
            let out_script = p2tr_script(20_000u32.saturating_add(height));
            remember(out_script.clone());
            txs.push(TxFacts {
                txid: chain_txid(height, 0x52),
                offset: 420,
                len: 130,
                inputs: vec![SpentPrevout {
                    txid: chain_txid(prev, 0xC0),
                    vout: 1,
                    value: 25_000,
                    script,
                    height: prev,
                    coinbase: false,
                }],
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: 24_000,
                    script: out_script,
                }],
            });
            spent.push((chain_txid(prev, 0xC0), 1));
        }
        blocks.push(CommittedBlock {
            height,
            hash,
            parent_hash,
            header: [0u8; 80],
            txs,
        });
    }
    SpendChain {
        blocks,
        scripts,
        spent,
    }
}

fn publish_rebuild_index_generation<S: KvStore>(
    store: &S,
    gen_id: u64,
    coverage: Coverage,
    blocks: &[CommittedBlock],
) -> Result<(), TestError> {
    let next_ordinal = u32::try_from(blocks.iter().map(|block| block.txs.len()).sum::<usize>())?;
    bitcoin_rs_projection::segment::publish_bulk_generation(
        store,
        gen_id,
        coverage,
        next_ordinal,
        IndexCapabilities::ALL,
    )?;
    Ok(())
}

fn count_rows<S: KvStore>(store: &S, cf: ColumnFamily, prefix: &[u8]) -> Result<u64, TestError> {
    let snapshot = store.snapshot()?;
    let mut total = 0u64;
    for item in snapshot.iter_prefix(cf, prefix)? {
        let _ = item?;
        total = total.saturating_add(1);
    }
    Ok(total)
}

fn family_totals<S: KvStore>(store: &S) -> Result<Vec<(ColumnFamily, u64)>, TestError> {
    let mut out = Vec::new();
    for cf in [
        ColumnFamily::TxDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
        ColumnFamily::IdxMeta,
    ] {
        out.push((cf, count_rows(store, cf, &[])?));
    }
    Ok(out)
}

fn gen_zero_totals<S: KvStore>(store: &S) -> Result<Vec<(ColumnFamily, u64)>, TestError> {
    let prefix = 0u64.to_be_bytes();
    let mut out = Vec::new();
    for cf in [
        ColumnFamily::TxDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
    ] {
        out.push((cf, count_rows(store, cf, &prefix)?));
    }
    Ok(out)
}

fn catch_up_from_watermarks<S: KvStore>(
    writer: &mut IndexWriter<S>,
    blocks: &[CommittedBlock],
    coverage: &Coverage,
    caps: IndexCapabilities,
) -> Result<usize, TestError> {
    let marks = writer.watermarks()?;
    let mut start = coverage.last_height.saturating_add(1);
    for mark in [marks.tx_lookup, marks.script_history, marks.compact_filters] {
        let next = mark.map_or(coverage.first_height, |watermark| {
            watermark.height.saturating_add(1)
        });
        start = start.min(next);
    }
    if start > coverage.last_height {
        return Ok(0);
    }
    let first = usize::try_from(start.saturating_sub(coverage.first_height))?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: usize::MAX,
        max_bytes: usize::MAX,
    });
    for block in &blocks[first..] {
        let prepared = writer.prepare_block_from_facts(caps, block.clone())?;
        batch
            .try_push(prepared)
            .map_err(|_| TestError::Message("catch-up batch must admit the block".to_owned()))?;
    }
    let caught = blocks.len().saturating_sub(first);
    writer.commit_forward(batch)?;
    Ok(caught)
}

fn scan_pairs(rows: Vec<TxIndexScanRow>) -> Vec<(u32, Vec<u8>)> {
    let mut pairs: Vec<(u32, Vec<u8>)> = rows
        .into_iter()
        .map(|row| (row.row.height(), row.value))
        .collect();
    pairs.sort();
    pairs
}

// PRJ-05, PRJ-09
#[test]
fn published_bulk_generation_needs_no_reindex_on_open() -> Result<(), TestError> {
    const HEIGHTS: u32 = 300;
    const GEN_ID: u64 = 1;
    const SCAN_ALL: PrefixScanLimit = PrefixScanLimit {
        max_rows: 100_000,
        max_bytes: 64 << 20,
    };
    let chain = create_spend_chain(HEIGHTS);
    let caps = IndexCapabilities::HISTORICAL.with_compact_filters(true);

    let dir_bulk = tempdir()?;
    let scratch_bulk = tempdir()?;
    let seal_scratch = tempdir()?;
    let store = Arc::new(RocksDbStore::open(dir_bulk.path())?);
    let builder = BulkSegmentBuilder::new(
        Arc::new(UnboundedBudget),
        None,
        scratch_bulk.path().to_path_buf(),
    );
    let coverage = builder
        .build_and_ingest(store.as_ref(), GEN_ID, &chain.blocks)
        .map_err(|e| e.to_string())?;
    publish_rebuild_index_generation(store.as_ref(), GEN_ID, coverage, &chain.blocks)?;
    let before = family_totals(store.as_ref())?;
    let gen_zero_before = gen_zero_totals(store.as_ref())?;
    for (cf, rows) in &gen_zero_before {
        assert_eq!(*rows, 0, "{cf:?} must hold no tail rows before open");
    }

    let mut writer = IndexWriter::open(Arc::clone(&store), GEN_ID)?
        .with_seal_scratch(seal_scratch.path().to_path_buf());
    writer.restore_tail_bounds()?;

    let tip = IndexWatermark {
        height: coverage.last_height,
        hash: coverage.last_hash,
    };
    let marks = writer.watermarks()?;
    assert_eq!(
        marks.tx_lookup,
        Some(tip),
        "tx_lookup must stay covered after open"
    );
    assert_eq!(
        marks.script_history,
        Some(tip),
        "script_history must stay covered after open"
    );
    assert_eq!(
        marks.compact_filters,
        Some(tip),
        "compact_filters must stay covered after open"
    );
    let snapshot = store.snapshot()?;
    for cap in [
        IndexCapability::TxLookup,
        IndexCapability::ScriptHistory,
        IndexCapability::CompactFilters,
    ] {
        let sealed = sealed_generations(snapshot.as_ref(), cap)?;
        assert_eq!(
            sealed.len(),
            1,
            "{cap:?} must publish one sealed generation"
        );
        assert_eq!(
            sealed[0].coverage, coverage,
            "{cap:?} sealed coverage must span the bulk range"
        );
    }
    drop(snapshot);

    let caught = catch_up_from_watermarks(&mut writer, &chain.blocks, &coverage, caps)?;
    assert_eq!(caught, 0, "covered heights need no catch-up writes");

    let after = family_totals(store.as_ref())?;
    assert!(
        before.iter().any(|(_, rows)| *rows > 0),
        "the bulk build writes rows before open"
    );
    assert_eq!(
        before, after,
        "node open must not write rows for bulk-covered heights"
    );

    let dir_live = tempdir()?;
    let scratch_live = tempdir()?;
    let live = Arc::new(RocksDbStore::open(dir_live.path())?);
    let mut tail_state = TailWriterState::new();
    for block in &chain.blocks {
        let mut batch = live.new_batch();
        append_tail_block(&mut batch, block, &mut tail_state, &NoSealedTxOrdinals)?;
        live.write_durable(batch)?;
    }
    seal_tail_generation(
        live.as_ref(),
        GEN_ID,
        coverage.last_height,
        caps,
        scratch_live.path(),
    )?;
    for cf in [
        ColumnFamily::TxDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
    ] {
        let (sealed_digest, sealed_rows) = compute_family_digest(store.as_ref(), cf, GEN_ID)?;
        let (live_digest, live_rows) = compute_family_digest(live.as_ref(), cf, GEN_ID)?;
        assert!(sealed_rows > 0, "{cf:?} has no sealed rows after open");
        assert_eq!(sealed_rows, live_rows, "row count differs on {cf:?}");
        assert_eq!(sealed_digest, live_digest, "mismatch on {cf:?}");
    }

    let bulk_indexer = Indexer::new(Arc::clone(&store));
    let bulk_view = bulk_indexer.snapshot()?;
    let live_indexer = Indexer::new(Arc::clone(&live));
    let live_view = live_indexer.snapshot()?;
    for script in &chain.scripts {
        let scripthash = ScriptHash::from_script_bytes(script.as_ref());
        let actual = scan_pairs(bulk_view.funding_rows(scripthash, SCAN_ALL)?.rows);
        let expected = scan_pairs(live_view.funding_rows(scripthash, SCAN_ALL)?.rows);
        assert!(!actual.is_empty(), "bulk history must be non-empty");
        assert_eq!(
            actual, expected,
            "funding history must match the live build"
        );
    }
    for (txid, vout) in &chain.spent {
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(txid)), *vout);
        let actual = scan_pairs(bulk_view.spending_rows(&outpoint, SCAN_ALL)?.rows);
        let expected = scan_pairs(live_view.spending_rows(&outpoint, SCAN_ALL)?.rows);
        assert!(!actual.is_empty(), "bulk spend must be non-empty");
        assert_eq!(
            actual, expected,
            "spending history must match the live build"
        );
    }
    for block in &chain.blocks {
        assert_eq!(
            bulk_view.compact_filter(block.height, &block.hash)?,
            live_view.compact_filter(block.height, &block.hash)?,
            "compact filter must match the live build at height {}",
            block.height
        );
        assert!(
            bulk_view
                .compact_filter(block.height, &block.hash)?
                .is_some(),
            "bulk filter must exist at height {}",
            block.height
        );
    }
    Ok(())
}

struct CrashAtDurableWrite {
    inner: RocksDbStore,
    crash_at: usize,
    durable_writes: AtomicU64,
    crashed: AtomicBool,
}

impl KvStore for CrashAtDurableWrite {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(cf, key)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<bitcoin_rs_storage::KvIter<'a>, StorageError> {
        self.inner.iter_prefix(cf, prefix)
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<bitcoin_rs_storage::PrefixScan, StorageError> {
        self.inner
            .scan_prefix_from_bounded(cf, prefix, start, limit)
    }

    fn new_batch(&self) -> bitcoin_rs_storage::BufferedWriteBatch {
        self.inner.new_batch()
    }

    fn write(&self, batch: bitcoin_rs_storage::BufferedWriteBatch) -> Result<(), StorageError> {
        self.inner.write(batch)
    }

    fn write_durable(
        &self,
        batch: bitcoin_rs_storage::BufferedWriteBatch,
    ) -> Result<(), StorageError> {
        let ordinal = usize::try_from(self.durable_writes.fetch_add(1, Ordering::SeqCst) + 1)
            .unwrap_or(usize::MAX);
        if ordinal == self.crash_at {
            self.crashed.store(true, Ordering::SeqCst);
            return Err(StorageError::Backend("injected crash".to_owned()));
        }
        self.inner.write_durable(batch)
    }

    fn write_durable_if(
        &self,
        conditions: &[bitcoin_rs_storage::WriteCondition<'_>],
        batch: bitcoin_rs_storage::BufferedWriteBatch,
    ) -> Result<bool, StorageError> {
        self.inner.write_durable_if(conditions, batch)
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.inner.flush()
    }

    fn snapshot(&self) -> Result<Box<dyn bitcoin_rs_storage::KvSnapshot + '_>, StorageError> {
        self.inner.snapshot()
    }

    fn multi_get(
        &self,
        cf: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<bitcoin_rs_storage::Bytes>>, StorageError> {
        self.inner.multi_get(cf, keys)
    }

    fn ingest_sorted(
        &self,
        cf: ColumnFamily,
        rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        scratch: &std::path::Path,
    ) -> Result<u64, StorageError> {
        self.inner.ingest_sorted(cf, rows, scratch)
    }

    fn delete_range(&self, cf: ColumnFamily, start: &[u8], end: &[u8]) -> Result<(), StorageError> {
        self.inner.delete_range(cf, start, end)
    }

    fn checkpoint(&self, dir: &std::path::Path) -> Result<(), StorageError> {
        self.inner.checkpoint(dir)
    }

    fn engine_cache_bytes(&self) -> u64 {
        self.inner.engine_cache_bytes()
    }

    fn arm_persist_fault(&self, fault: bitcoin_rs_storage::PersistFault) {
        self.inner.arm_persist_fault(fault);
    }
}

// PRJ-05, PRJ-09
#[test]
fn bulk_publish_is_all_or_nothing_across_a_crash() -> Result<(), TestError> {
    const HEIGHTS: u32 = 60;
    const GEN_ID: u64 = 1;
    let chain = create_spend_chain(HEIGHTS);
    let next_ordinal = u32::try_from(
        chain
            .blocks
            .iter()
            .map(|block| block.txs.len())
            .sum::<usize>(),
    )?;
    let writes_observed = {
        let dir = tempdir()?;
        let scratch = tempdir()?;
        let store = Arc::new(CrashAtDurableWrite {
            inner: RocksDbStore::open(dir.path())?,
            crash_at: usize::MAX,
            durable_writes: AtomicU64::new(0),
            crashed: AtomicBool::new(false),
        });
        let coverage = BulkSegmentBuilder::new(
            Arc::new(UnboundedBudget),
            None,
            scratch.path().to_path_buf(),
        )
        .build_and_ingest(store.as_ref(), GEN_ID, &chain.blocks)
        .map_err(|e| e.to_string())?;
        bitcoin_rs_projection::segment::publish_bulk_generation(
            store.as_ref(),
            GEN_ID,
            coverage,
            next_ordinal,
            IndexCapabilities::ALL,
        )
        .map_err(|e| e.to_string())?;
        store.durable_writes.load(Ordering::SeqCst)
    };
    assert!(
        writes_observed > 0,
        "the clean run must observe at least one durable publish write"
    );
    let mut crash_points = Vec::new();
    for point in 1..=writes_observed {
        crash_points.push(usize::try_from(point)?);
    }
    crash_points.push(usize::MAX);
    for crash_at in crash_points {
        let dir = tempdir()?;
        let scratch = tempdir()?;
        let seal_scratch = tempdir()?;
        let store = Arc::new(CrashAtDurableWrite {
            inner: RocksDbStore::open(dir.path())?,
            crash_at,
            durable_writes: AtomicU64::new(0),
            crashed: AtomicBool::new(false),
        });
        let coverage = BulkSegmentBuilder::new(
            Arc::new(UnboundedBudget),
            None,
            scratch.path().to_path_buf(),
        )
        .build_and_ingest(store.as_ref(), GEN_ID, &chain.blocks)
        .map_err(|e| e.to_string())?;
        let publish = bitcoin_rs_projection::segment::publish_bulk_generation(
            store.as_ref(),
            GEN_ID,
            coverage,
            next_ordinal,
            IndexCapabilities::ALL,
        );
        if crash_at == usize::MAX {
            assert!(
                !store.crashed.load(Ordering::SeqCst),
                "the clean publish must not trip the crash injection"
            );
        } else {
            assert!(
                store.crashed.load(Ordering::SeqCst),
                "crash point {crash_at} never fired during publish"
            );
            let Err(error) = publish else {
                panic!("publish at crash_at {crash_at} must fail on the injected crash");
            };
            let IndexError::Storage(storage) = &error else {
                panic!("publish failed for a reason other than the injected crash: {error}");
            };
            let StorageError::Backend(detail) = storage else {
                panic!("publish failed with a storage error other than the crash: {error}");
            };
            assert_eq!(
                detail.as_str(),
                "injected crash",
                "publish must fail at the injected durable write"
            );
        }

        let published_records = {
            let snapshot = store.snapshot()?;
            !sealed_generations(snapshot.as_ref(), IndexCapability::TxLookup)?.is_empty()
        };
        let marks = Indexer::new(Arc::clone(&store)).watermarks()?;
        let watermarked = [marks.tx_lookup, marks.script_history, marks.compact_filters];
        if !published_records {
            assert!(
                watermarked.iter().all(Option::is_none),
                "crash at durable write {crash_at} left a watermark without sealed records"
            );
            continue;
        }
        let mut writer = IndexWriter::open(Arc::clone(&store), GEN_ID)?
            .with_seal_scratch(seal_scratch.path().to_path_buf());
        writer.restore_tail_bounds()?;
        let before = family_totals(store.as_ref())?;
        assert!(
            before.iter().any(|(_, rows)| *rows > 0),
            "the bulk build writes rows before the crash"
        );
        let caught = catch_up_from_watermarks(
            &mut writer,
            &chain.blocks,
            &coverage,
            IndexCapabilities::ALL,
        )?;
        assert_eq!(
            caught, 0,
            "reopen at crash_at {crash_at} must not rewrite covered heights"
        );
        assert_eq!(
            before,
            family_totals(store.as_ref())?,
            "reopen after crash at durable write {crash_at} must not rewrite covered heights"
        );
    }
    Ok(())
}
