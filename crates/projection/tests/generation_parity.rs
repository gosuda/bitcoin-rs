use bitcoin_rs_projection::IndexCapabilities;
use bitcoin_rs_projection::segment::bulk_builder::{BulkSegmentBuilder, StreamingSegmentBuilder};
use bitcoin_rs_projection::segment::{
    Coverage, NoSealedTxOrdinals, TailWriterState, append_tail_block, meta_gen_key,
    seal_tail_generation,
};
use bitcoin_rs_storage::budget::{BudgetCharge, BudgetError, BudgetOwner, UnboundedBudget};
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, SpentPrevout, TxFacts};
use bitcoin_rs_storage::{Bytes, ColumnFamily, KvStore, RocksDbStore};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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

fn hash_cf_entry(hasher: &mut Sha256, k: &[u8], v: &[u8]) {
    let Ok(k_len) = u32::try_from(k.len()) else {
        return;
    };
    let Ok(v_len) = u32::try_from(v.len()) else {
        return;
    };
    hasher.update(k_len.to_le_bytes());
    hasher.update(k);
    hasher.update(v_len.to_le_bytes());
    hasher.update(v);
}

fn compute_family_digest<S: KvStore>(store: &S, cf: ColumnFamily, gen_id: u64) -> [u8; 32] {
    let start = gen_id.to_be_bytes();
    let end = gen_id.saturating_add(1).to_be_bytes();
    let mut hasher = Sha256::new();
    let Ok(snapshot) = store.snapshot() else {
        return hasher.finalize().into();
    };
    let Ok(iter) = snapshot.iter_prefix(cf, &start) else {
        return hasher.finalize().into();
    };
    for item in iter {
        let Ok((k, v)) = item else {
            continue;
        };
        if k.as_slice() >= end.as_slice() {
            break;
        }
        hash_cf_entry(&mut hasher, &k, &v);
    }
    hasher.finalize().into()
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
        let digest_a = compute_family_digest(&store_a, cf, gen_id);
        let digest_b = compute_family_digest(&store_b, cf, gen_id);
        assert_eq!(digest_a, digest_b, "mismatch on {:?}", cf);
    }
    Ok(())
}

struct FamilyDigestPair {
    family: ColumnFamily,
    tail: [u8; 32],
    bulk: [u8; 32],
}

fn cross_block_spend_generation() -> Vec<CommittedBlock> {
    vec![CommittedBlock {
        height: 1,
        hash: [0x71; 32],
        parent_hash: [0u8; 32],
        header: [0u8; 80],
        txs: vec![TxFacts {
            txid: [0xD1; 32],
            offset: 0,
            len: 120,
            inputs: vec![SpentPrevout {
                txid: [0x99; 32],
                vout: 3,
                value: 20_000,
                script: Bytes::copy_from_slice(b"\x51older_coin_script"),
                height: 0,
                coinbase: false,
            }],
            outputs: vec![CreatedOutput {
                vout: 0,
                value: 19_000,
                script: Bytes::copy_from_slice(b"\x76\xa9\x14fresh_output\x88\xac"),
            }],
        }],
    }]
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

    Ok(indexed_cfs
        .iter()
        .map(|&cf| FamilyDigestPair {
            family: cf,
            tail: compute_family_digest(&store_tail, cf, gen_id),
            bulk: compute_family_digest(&store_bulk, cf, gen_id),
        })
        .collect())
}

// PRJ-09
#[test]
fn cross_block_spends_produce_identical_tail_and_bulk_segments() -> Result<(), TestError> {
    let blocks = cross_block_spend_generation();
    for pair in tail_seal_and_bulk_family_digests(&blocks, 1)? {
        assert_eq!(
            pair.tail, pair.bulk,
            "{:?} diverges on cross-block spend",
            pair.family
        );
    }
    Ok(())
}

// PRJ-09
#[test]
fn same_tx_fund_and_spend_keeps_both_posting_occurrences() -> Result<(), TestError> {
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
        assert_eq!(
            pair.tail, pair.bulk,
            "{:?} diverges on same-tx fund and spend",
            pair.family
        );
        if pair.family == ColumnFamily::ScriptStats {
            assert_ne!(pair.bulk, [0u8; 32], "stats row missing");
        }
    }
    Ok(())
}

// PRJ-08
#[test]
fn seal_repack_respects_posting_chunk_byte_cap() -> Result<(), TestError> {
    use bitcoin_rs_projection::segment::format::{
        SCRIPT_POST_CHUNK_MAX_BYTES, decode_posting_items, decode_script_post_key,
    };

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
        writer.prepare_block_from_facts(IndexCapabilities::ALL, &one_script_block(occurrences))?;
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
            value.len() <= SCRIPT_POST_CHUNK_MAX_BYTES,
            "sealed chunk is {} bytes, cap is {}",
            value.len(),
            SCRIPT_POST_CHUNK_MAX_BYTES
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
    digests: Vec<(ColumnFamily, [u8; 32])>,
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
    let digests = cfs
        .iter()
        .map(|&cf| (cf, compute_family_digest(&store, cf, gen_id)))
        .collect();
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
    builder
        .build_and_ingest(&store, 1, &blocks)
        .map_err(|e| e.to_string())?;

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
