use super::format::*;

// PRJ-08
#[test]
fn posting_holds_reference_and_flags_only() {
    let gen_id = 1u64;
    let script_id = 42u32;
    let chunk = 0u32;
    let key = encode_script_post_key(gen_id, script_id, chunk);

    assert_eq!(key.len(), SCRIPT_POST_KEY_LEN);
    assert_eq!(key.len(), 16);
    assert!(key.len() < 32);

    let items = vec![
        PostingItem {
            delta_ordinal: 10,
            flags: POSTING_FLAG_FUNDING,
        },
        PostingItem {
            delta_ordinal: 5,
            flags: POSTING_FLAG_SPENDING,
        },
    ];

    let encoded = encode_posting_items(&items);
    let Some(decoded) = decode_posting_items(&encoded) else {
        panic!("posting decode failed");
    };
    assert_eq!(decoded, items);

    for item in decoded {
        assert!(item.flags == POSTING_FLAG_FUNDING || item.flags == POSTING_FLAG_SPENDING);
    }
}

#[test]
#[expect(clippy::expect_used)]
fn history_pages_walk_more_than_256_posting_chunks() {
    use crate::segment::import::{
        TxOccurrence, next_segment_id, put_segment, stage_segment, tx_lookup_segment,
    };
    use crate::segment::{Coverage, SegmentSnapshot};
    use crate::types::{ScriptHash, TxPosition};
    use crate::{IndexCapabilities, IndexCapability, TxIndexSnapshot};
    use bitcoin_rs_storage::{ColumnFamily, KvStore, PrefixScanLimit, RocksDbStore};

    const TXS: u32 = 300;
    let dir = tempfile::tempdir().expect("tempdir");
    let store = RocksDbStore::open(dir.path()).expect("open store");
    let script = ScriptHash::from_script_bytes(b"paging script");
    let coverage = Coverage::new(1, TXS, [7_u8; 32]);
    let occurrences: Vec<TxOccurrence> = (0..TXS)
        .map(|index| {
            let mut txid = [0_u8; 32];
            txid[..4].copy_from_slice(&index.to_be_bytes());
            TxOccurrence {
                txid,
                height: index + 1,
                block_hash: [9; 32],
                position: TxPosition::new(0, 10),
            }
        })
        .collect();
    let mut segment = tx_lookup_segment(occurrences, coverage, 0).expect("tx segment");
    let dict_row = (
        encode_script_dict_key(0, &script.to_byte_array()).to_vec(),
        encode_script_dict_value(0).to_vec(),
    );
    let post_rows: Vec<(Vec<u8>, Vec<u8>)> = (0..TXS)
        .map(|chunk| {
            let item = PostingItem {
                delta_ordinal: 0,
                flags: POSTING_FLAG_FUNDING,
            };
            (
                encode_script_post_chunk_key(0, 0, chunk).to_vec(),
                encode_posting_items(&[item]),
            )
        })
        .collect();
    segment
        .families
        .push((ColumnFamily::ScriptDict, vec![dict_row]));
    segment.families.push((ColumnFamily::ScriptPost, post_rows));
    let caps = IndexCapabilities::TX_LOOKUP.insert(IndexCapability::ScriptHistory);
    let gen_id = next_segment_id(&store).expect("segment id");
    stage_segment(&store, gen_id, &segment, dir.path()).expect("stage segment");
    let mut batch = store.new_batch();
    put_segment(&mut batch, gen_id, &segment, caps);
    store.write_durable(batch).expect("publish segment");

    let snapshot = SegmentSnapshot::open(store.snapshot().expect("snapshot")).expect("open view");
    let page_of = |max_rows| PrefixScanLimit {
        max_rows,
        max_bytes: usize::MAX,
    };
    let mut seen = Vec::new();
    let mut page = snapshot
        .funding_rows(script, page_of(7))
        .expect("first page");
    loop {
        seen.extend(page.rows.iter().map(|row| row.row.height()));
        if page.complete {
            break;
        }
        let last = page
            .rows
            .last()
            .expect("a truncated page holds rows")
            .row
            .height();
        page = snapshot
            .funding_rows_from(script, last.saturating_sub(1), page_of(7))
            .expect("next page");
    }
    assert_eq!(seen, (1..=TXS).rev().collect::<Vec<u32>>());
    let unpaged = snapshot
        .funding_rows(script, page_of(usize::MAX))
        .expect("unpaged history");
    assert!(unpaged.complete);
    assert_eq!(unpaged.rows.len(), usize::try_from(TXS).unwrap_or(0));
}

#[test]
#[expect(clippy::expect_used)]
fn restore_orphan_cleanup_deletes_only_the_pending_segment() {
    use super::{
        Coverage, SEAL_NEXT_GEN_KEY, SealedGen, encode_sealed_gen, retire_generation,
        retire_tombstone_key, sealed_gen_key,
    };
    use crate::segment::import::{
        FamilyRows, ImportedSegment, clear_unpublished_segment_rows, next_segment_id, put_segment,
        stage_segment,
    };
    use crate::{IndexCapabilities, IndexCapability};
    use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore};

    const SEGMENT_FAMILIES: [ColumnFamily; 6] = [
        ColumnFamily::TxDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
    ];

    fn keyed(gen_id: u64, tag: u8, families: &[ColumnFamily]) -> Vec<(ColumnFamily, FamilyRows)> {
        families
            .iter()
            .map(|&cf| {
                let rows: FamilyRows = (0_u8..3)
                    .map(|index| {
                        let mut key = gen_id.to_be_bytes().to_vec();
                        key.extend_from_slice(&[tag, index, 0xA5]);
                        (key, vec![tag, index, 0x5A])
                    })
                    .collect();
                (cf, rows)
            })
            .collect()
    }

    fn restored(
        tag: u8,
        families: &[ColumnFamily],
        coverage: Coverage,
        next_ordinal: u32,
    ) -> ImportedSegment {
        let families = keyed(0, tag, families);
        let records = families
            .iter()
            .map(|(_, rows)| u64::try_from(rows.len()).unwrap_or(u64::MAX))
            .sum();
        ImportedSegment {
            coverage,
            next_ordinal,
            records,
            families,
        }
    }

    fn rows_under(store: &RocksDbStore, cf: ColumnFamily, gen_id: u64) -> FamilyRows {
        store
            .iter_prefix(cf, &gen_id.to_be_bytes())
            .expect("prefix scan")
            .collect::<Result<FamilyRows, _>>()
            .expect("prefix rows")
    }

    fn assert_rows(store: &RocksDbStore, gen_id: u64, expected: &[(ColumnFamily, FamilyRows)]) {
        for (cf, rows) in expected {
            assert_eq!(rows_under(store, *cf, gen_id), *rows);
        }
    }

    fn assert_meta(
        store: &RocksDbStore,
        gen_id: u64,
        record: &[u8],
        counter: u64,
        caps: IndexCapabilities,
    ) {
        assert_eq!(
            store
                .get(ColumnFamily::IdxMeta, SEAL_NEXT_GEN_KEY)
                .expect("read counter"),
            Some(counter.to_le_bytes().to_vec())
        );
        for capability in caps.iter() {
            assert_eq!(
                store
                    .get(ColumnFamily::IdxMeta, &sealed_gen_key(capability, gen_id))
                    .expect("read sealed record"),
                Some(record.to_vec())
            );
            assert_eq!(
                store
                    .get(
                        ColumnFamily::IdxMeta,
                        &retire_tombstone_key(capability, gen_id)
                    )
                    .expect("read retirement marker"),
                Some(Vec::new())
            );
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let store = RocksDbStore::open(dir.path()).expect("open store");
    let caps = IndexCapabilities::TX_LOOKUP
        .insert(IndexCapability::ScriptHistory)
        .insert(IndexCapability::CompactFilters);

    let g1 = next_segment_id(&store).expect("first generation id");
    let g1_coverage = Coverage::new(1, 10, [1_u8; 32]);
    let g1_segment = restored(0x11, &SEGMENT_FAMILIES, g1_coverage, 5);
    stage_segment(&store, g1, &g1_segment, dir.path()).expect("stage G1");
    let mut batch = store.new_batch();
    put_segment(&mut batch, g1, &g1_segment, caps);
    for capability in caps.iter() {
        batch.put(
            ColumnFamily::IdxMeta,
            &retire_tombstone_key(capability, g1),
            &[],
        );
    }
    store
        .write_durable(batch)
        .expect("publish G1 with retirement marker");

    let g2 = next_segment_id(&store).expect("second generation id");
    let g2_segment = restored(
        0x22,
        &[ColumnFamily::TxDir],
        Coverage::new(11, 12, [2_u8; 32]),
        7,
    );
    stage_segment(&store, g2, &g2_segment, dir.path()).expect("stage G2");
    let mut batch = store.new_batch();
    put_segment(&mut batch, g2, &g2_segment, IndexCapabilities::TX_LOOKUP);
    store.write_durable(batch).expect("publish G2");
    retire_generation(&store, IndexCapability::TxLookup, g2).expect("retire G2");

    let pending = next_segment_id(&store).expect("pending generation id");
    assert_eq!(
        pending,
        g2.saturating_add(1),
        "retired id must not be reissued"
    );
    let pending_segment = restored(
        0x33,
        &SEGMENT_FAMILIES,
        Coverage::new(13, 20, [3_u8; 32]),
        9,
    );
    stage_segment(&store, pending, &pending_segment, dir.path()).expect("stage pending segment");

    let g1_rows = keyed(g1, 0x11, &SEGMENT_FAMILIES);
    let pending_rows = keyed(pending, 0x33, &SEGMENT_FAMILIES);
    let g1_record = encode_sealed_gen(&SealedGen {
        gen_id: g1,
        coverage: g1_coverage,
        next_ordinal: 5,
    });

    assert_rows(&store, g1, &g1_rows);
    assert_rows(&store, pending, &pending_rows);
    assert_meta(&store, g1, &g1_record, pending, caps);
    assert!(
        store
            .get(
                ColumnFamily::IdxMeta,
                &sealed_gen_key(IndexCapability::TxLookup, g2)
            )
            .expect("read retired record")
            .is_none()
    );

    clear_unpublished_segment_rows(&store).expect("orphan cleanup");

    for cf in SEGMENT_FAMILIES {
        assert!(
            rows_under(&store, cf, pending).is_empty(),
            "pending rows survived orphan cleanup"
        );
    }
    assert_rows(&store, g1, &g1_rows);
    assert_meta(&store, g1, &g1_record, pending, caps);
    assert_eq!(
        next_segment_id(&store).expect("counter after cleanup"),
        pending
    );
}

#[test]
fn core_filter_vectors_read_back_through_the_segment_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::segment::SegmentSnapshot;
    use crate::segment::tail::{
        TailBounds, TailWriterState, append_tail_block, put_generation_descriptors,
    };
    use crate::{IndexCapability, TxIndexSnapshot};
    use bitcoin::{consensus::deserialize, hashes::Hash as _, hex::FromHex as _};
    use bitcoin_rs_storage::committed_facts::{
        CommittedBlock, CreatedOutput, SpentPrevout, TxFacts,
    };
    use bitcoin_rs_storage::{Bytes, KvStore, RocksDbStore};

    let vectors: Vec<sonic_rs::Value> =
        sonic_rs::from_str(include_str!("../../tests/data/blockfilters-core-31.1.json"))?;
    for vector in vectors.into_iter().skip(1) {
        let (height, _hash, body, prevouts, _previous, expected_filter, _header, note): (
            u32,
            String,
            String,
            Vec<String>,
            String,
            String,
            String,
            String,
        ) = sonic_rs::from_value(&vector)?;
        let bytes = Vec::from_hex(&body)?;
        let block: bitcoin::Block = deserialize(&bytes)?;
        let hash = block.block_hash().to_byte_array();
        let mut scripts = hashbrown::HashMap::<([u8; 32], u32), Vec<u8>>::new();
        for (input, script) in block
            .txdata
            .iter()
            .skip(1)
            .flat_map(|tx| &tx.input)
            .zip(prevouts)
        {
            scripts.insert(
                (
                    input.previous_output.txid.to_byte_array(),
                    input.previous_output.vout,
                ),
                Vec::from_hex(&script)?,
            );
        }
        let mut created = hashbrown::HashMap::<([u8; 32], u32), Bytes>::new();
        let mut txs = Vec::with_capacity(block.txdata.len());
        for (index, tx) in block.txdata.iter().enumerate() {
            let txid = tx.compute_txid().to_byte_array();
            let mut inputs = Vec::new();
            if index > 0 {
                for input in &tx.input {
                    let prev_txid = input.previous_output.txid.to_byte_array();
                    let prev_vout = input.previous_output.vout;
                    let script = created
                        .get(&(prev_txid, prev_vout))
                        .cloned()
                        .or_else(|| {
                            scripts
                                .get(&(prev_txid, prev_vout))
                                .map(|s| Bytes::copy_from_slice(s))
                        })
                        .ok_or("prevout script missing from the vector")?;
                    inputs.push(SpentPrevout {
                        txid: prev_txid,
                        vout: prev_vout,
                        value: 0,
                        script,
                        height: 0,
                        coinbase: false,
                    });
                }
            }
            let mut outputs = Vec::with_capacity(tx.output.len());
            for (vout, out) in tx.output.iter().enumerate() {
                let vout = u32::try_from(vout)?;
                let script = Bytes::copy_from_slice(out.script_pubkey.as_bytes());
                created.insert((txid, vout), script.clone());
                outputs.push(CreatedOutput {
                    vout,
                    value: out.value.to_sat(),
                    script,
                });
            }
            txs.push(TxFacts {
                txid,
                offset: 0,
                len: 0,
                inputs,
                outputs,
            });
        }

        let dir = tempfile::tempdir()?;
        let store = RocksDbStore::open(dir.path())?;
        let block_facts = CommittedBlock {
            height,
            hash,
            parent_hash: [0; 32],
            header: [0; 80],
            txs,
        };
        let mut state = TailWriterState::new();
        let mut batch = store.new_batch();
        append_tail_block(
            &mut batch,
            &block_facts,
            &mut state,
            &crate::segment::tail::NoSealedTxOrdinals,
        )?;
        put_generation_descriptors(
            &mut batch,
            [IndexCapability::CompactFilters],
            TailBounds {
                newest: None,
                first_height: Some(height),
                at: Some((height, hash)),
            },
        );
        store.write_durable(batch)?;

        let snapshot = SegmentSnapshot::open(store.snapshot()?)?;
        let filter = snapshot
            .compact_filter(height, &hash)?
            .ok_or("the segment holds no filter for a covered height")?;
        assert_eq!(filter.filter, Vec::from_hex(&expected_filter)?, "{note}");
    }
    Ok(())
}

fn committed_facts(
    block: &bitcoin::Block,
    height: u32,
    external: &hashbrown::HashMap<([u8; 32], u32), bitcoin_rs_storage::Bytes>,
) -> Result<bitcoin_rs_storage::CommittedBlock, crate::portable::TestError> {
    use bitcoin::hashes::Hash as _;
    use bitcoin_rs_storage::Bytes;
    use bitcoin_rs_storage::committed_facts::{CreatedOutput, SpentPrevout, TxFacts};

    let mut created = hashbrown::HashMap::<([u8; 32], u32), Bytes>::new();
    let mut txs = Vec::with_capacity(block.txdata.len());
    for tx in &block.txdata {
        let txid = tx.compute_txid().to_byte_array();
        let mut inputs = Vec::with_capacity(tx.input.len());
        for input in &tx.input {
            let prev_txid = input.previous_output.txid.to_byte_array();
            let vout = input.previous_output.vout;
            if prev_txid == [0; 32] && vout == u32::MAX {
                inputs.push(SpentPrevout {
                    txid: [0; 32],
                    vout: u32::MAX,
                    value: 0,
                    script: Bytes::new(),
                    height,
                    coinbase: true,
                });
                continue;
            }
            let script = created
                .get(&(prev_txid, vout))
                .cloned()
                .or_else(|| external.get(&(prev_txid, vout)).cloned())
                .ok_or("prevout script missing from the fixture")?;
            inputs.push(SpentPrevout {
                txid: prev_txid,
                vout,
                value: 0,
                script,
                height: 0,
                coinbase: false,
            });
        }
        let mut outputs = Vec::with_capacity(tx.output.len());
        for (vout, out) in tx.output.iter().enumerate() {
            let vout = u32::try_from(vout)?;
            let script = Bytes::copy_from_slice(out.script_pubkey.as_bytes());
            created.insert((txid, vout), script.clone());
            outputs.push(CreatedOutput {
                vout,
                value: out.value.to_sat(),
                script,
            });
        }
        txs.push(TxFacts {
            txid,
            offset: 0,
            len: 0,
            inputs,
            outputs,
        });
    }
    Ok(bitcoin_rs_storage::CommittedBlock {
        height,
        hash: block.block_hash().to_byte_array(),
        parent_hash: [0; 32],
        header: [0; 80],
        txs,
    })
}

fn append_and_read(
    block: &bitcoin_rs_storage::CommittedBlock,
) -> Result<crate::BasicFilter, crate::portable::TestError> {
    use crate::segment::SegmentSnapshot;
    use crate::segment::tail::{
        NoSealedTxOrdinals, TailBounds, TailWriterState, append_tail_block,
        put_generation_descriptors,
    };
    use crate::{IndexCapability, TxIndexSnapshot};
    use bitcoin_rs_storage::{KvStore, RocksDbStore};

    let dir = tempfile::tempdir()?;
    let store = RocksDbStore::open(dir.path())?;
    let mut state = TailWriterState::new();
    let mut batch = store.new_batch();
    append_tail_block(&mut batch, block, &mut state, &NoSealedTxOrdinals)?;
    put_generation_descriptors(
        &mut batch,
        [IndexCapability::CompactFilters],
        TailBounds {
            newest: None,
            first_height: Some(block.height),
            at: Some((block.height, block.hash)),
        },
    );
    store.write_durable(batch)?;
    let snapshot = SegmentSnapshot::open(store.snapshot()?)?;
    let filter = snapshot
        .compact_filter(block.height, &block.hash)?
        .ok_or("the segment holds no filter for a covered height")?;
    Ok(filter)
}

// PRJ-12
#[test]
fn oversized_scripts_stay_in_basic_filters() -> Result<(), crate::portable::TestError> {
    use bitcoin::ScriptBuf;

    let mut block = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
    block.txdata[0].output[0].script_pubkey =
        ScriptBuf::from_bytes(vec![0x51_u8; crate::MAX_LIVE_SCRIPT_SIZE + 1]);
    let facts = committed_facts(&block, 0, &hashbrown::HashMap::new())?;
    let filter = append_and_read(&facts)?;
    let oracle = bitcoin::bip158::BlockFilter::new_script_filter(&block, |outpoint| {
        Err::<ScriptBuf, _>(bitcoin::bip158::Error::UtxoMissing(*outpoint))
    })?;
    assert_eq!(filter.filter, oracle.content);
    Ok(())
}

fn shared_script_blocks(count: u32) -> Vec<bitcoin_rs_storage::CommittedBlock> {
    let script = bitcoin_rs_storage::Bytes::copy_from_slice(&[0x51]);
    let mut blocks = Vec::new();
    let mut previous_coinbase: Option<[u8; 32]> = None;
    let mut previous_hash = [0u8; 32];
    for height in 0..count {
        let mut coinbase_txid = [0u8; 32];
        coinbase_txid[..4].copy_from_slice(&(height * 2 + 1).to_le_bytes());
        let mut spend_txid = [0u8; 32];
        spend_txid[..4].copy_from_slice(&(height * 2 + 2).to_le_bytes());
        let coinbase = bitcoin_rs_storage::committed_facts::TxFacts {
            txid: coinbase_txid,
            offset: 0,
            len: 1,
            inputs: Vec::new(),
            outputs: vec![bitcoin_rs_storage::committed_facts::CreatedOutput {
                vout: 0,
                value: 1,
                script: script.clone(),
            }],
        };
        let inputs = previous_coinbase
            .map(|txid| bitcoin_rs_storage::committed_facts::SpentPrevout {
                txid,
                vout: 0,
                value: 1,
                script: script.clone(),
                height: height.saturating_sub(1),
                coinbase: true,
            })
            .into_iter()
            .collect();
        let spend = bitcoin_rs_storage::committed_facts::TxFacts {
            txid: spend_txid,
            offset: 1,
            len: 1,
            inputs,
            outputs: vec![bitcoin_rs_storage::committed_facts::CreatedOutput {
                vout: 0,
                value: 1,
                script: script.clone(),
            }],
        };
        let mut hash = [0u8; 32];
        hash[..4].copy_from_slice(&(height + 1).to_le_bytes());
        blocks.push(bitcoin_rs_storage::CommittedBlock {
            height,
            hash,
            parent_hash: previous_hash,
            header: [0u8; 80],
            txs: vec![coinbase, spend],
        });
        previous_coinbase = Some(coinbase_txid);
        previous_hash = hash;
    }
    blocks
}

// PRJ-05, PRJ-09
#[test]
#[expect(clippy::expect_used)]
fn window_history_for_a_shared_script_matches_bulk() {
    use super::read::SegmentSnapshot;
    use crate::segment::bulk_builder::BulkSegmentBuilder;
    use bitcoin_rs_storage::KvStore as _;

    let blocks = shared_script_blocks(6);
    let dir = tempfile::tempdir().expect("dir");
    let scratch = tempfile::tempdir().expect("scratch");
    let store =
        std::sync::Arc::new(bitcoin_rs_storage::RocksDbStore::open(dir.path()).expect("store"));
    let mut writer = crate::IndexWriter::open(std::sync::Arc::clone(&store), 1)
        .expect("writer")
        .with_seal_scratch(scratch.path().to_path_buf());
    for block in &blocks {
        let prepared = writer
            .prepare_block_from_facts(crate::IndexCapabilities::ALL, block)
            .expect("prepare");
        let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        assert!(batch.try_push(prepared).is_ok(), "contiguous block");
        writer.commit_forward(batch).expect("commit");
    }
    super::seal_tail_generation(
        store.as_ref(),
        1,
        2,
        crate::IndexCapabilities::ALL,
        scratch.path(),
    )
    .expect("seal");

    let bulk_dir = tempfile::tempdir().expect("bulk dir");
    let bulk_scratch = tempfile::tempdir().expect("bulk scratch");
    let bulk = bitcoin_rs_storage::RocksDbStore::open(bulk_dir.path()).expect("bulk store");
    let builder = BulkSegmentBuilder::new(
        std::sync::Arc::new(bitcoin_rs_storage::budget::UnboundedBudget),
        None,
        bulk_scratch.path().to_path_buf(),
    );
    let coverage = builder
        .build_and_ingest(&bulk, 1, &blocks)
        .expect("bulk build");
    super::publish_sealed(
        &bulk,
        1,
        coverage,
        6 * 2,
        crate::IndexCapabilities::HISTORICAL,
    )
    .expect("publish bulk");

    let live_view = SegmentSnapshot::open(store.snapshot().expect("live snap")).expect("live");
    let bulk_view = SegmentSnapshot::open(bulk.snapshot().expect("bulk snap")).expect("bulk");
    let hash = crate::ScriptHash::from_script_bytes(&[0x51]);
    let live_history = live_view
        .history_answer_for_test(hash)
        .expect("live history");
    let bulk_history = bulk_view
        .history_answer_for_test(hash)
        .expect("bulk history");
    assert_eq!(
        live_history, bulk_history,
        "live window and sealed history equal the bulk build"
    );
}

fn dense_block(
    height: u32,
    previous_hash: [u8; 32],
    outputs: u32,
) -> bitcoin_rs_storage::CommittedBlock {
    let mut hash = [0u8; 32];
    hash[..4].copy_from_slice(&(height + 1).to_le_bytes());
    let mut txid = [0u8; 32];
    txid[..4].copy_from_slice(&(height * 2 + 1).to_le_bytes());
    let created = (0..outputs)
        .map(|vout| {
            let mut script = [0u8; 12];
            script[..4].copy_from_slice(&height.to_le_bytes());
            script[4..8].copy_from_slice(&vout.to_le_bytes());
            bitcoin_rs_storage::committed_facts::CreatedOutput {
                vout,
                value: 1,
                script: bitcoin_rs_storage::Bytes::copy_from_slice(&script),
            }
        })
        .collect();
    bitcoin_rs_storage::CommittedBlock {
        height,
        hash,
        parent_hash: previous_hash,
        header: [0u8; 80],
        txs: vec![bitcoin_rs_storage::committed_facts::TxFacts {
            txid,
            offset: 0,
            len: 1,
            inputs: Vec::new(),
            outputs: created,
        }],
    }
}

#[expect(clippy::expect_used)]
fn tail_state<S: bitcoin_rs_storage::KvStore>(store: &S) -> crate::segment::tail::TailWriterState {
    let snapshot = store.snapshot().expect("snapshot");
    crate::segment::tail::load(snapshot.as_ref()).expect("tail state")
}
#[expect(clippy::expect_used)]
fn commit_one<S: bitcoin_rs_storage::KvStore>(
    writer: &mut crate::IndexWriter<S>,
    block: &bitcoin_rs_storage::CommittedBlock,
) {
    let prepared = writer
        .prepare_block_from_facts(crate::IndexCapabilities::ALL, block)
        .expect("prepare");
    let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
        max_rows: usize::MAX,
        max_bytes: usize::MAX,
    });
    assert!(batch.try_push(prepared).is_ok(), "contiguous block");
    writer.commit_forward(batch).expect("commit");
}

// PRJ-05
#[test]
#[expect(clippy::expect_used)]
fn large_blocks_keep_both_bounds_and_the_window_before_a_crossing_block() {
    const BLOCKS: u32 = 10;
    const OUTPUTS: u32 = 32_500;
    let max_blocks = usize::try_from(TAIL_MAX_BLOCKS).expect("block bound");
    let max_bytes = u64::try_from(TAIL_MAX_BYTES).expect("byte bound");
    let dir = tempfile::tempdir().expect("dir");
    let scratch = tempfile::tempdir().expect("scratch");
    let store =
        std::sync::Arc::new(bitcoin_rs_storage::RocksDbStore::open(dir.path()).expect("store"));
    let mut writer = crate::IndexWriter::open(std::sync::Arc::clone(&store), 1)
        .expect("writer")
        .with_seal_scratch(scratch.path().to_path_buf());
    let mut previous = [0u8; 32];
    let mut previous_bytes = 0_u64;
    let mut crossing_seen = false;
    for height in 0..BLOCKS {
        let block = dense_block(height, previous, OUTPUTS);
        previous = block.hash;
        commit_one(&mut writer, &block);
        let state = tail_state(store.as_ref());
        assert!(
            state.tail_bytes() <= max_bytes,
            "tail bytes {} after height {height}",
            state.tail_bytes()
        );
        assert!(
            state.tail_blocks() <= max_blocks,
            "tail blocks {} after height {height}",
            state.tail_blocks()
        );
        let after = state.tail_bytes();
        if !crossing_seen && after < previous_bytes {
            crossing_seen = true;
            assert!(
                after > TAIL_RETAIN_MAX_BYTES,
                "the commit that crosses the bound keeps the retained window ahead of the new block: {after} bytes"
            );
        }
        previous_bytes = after;
    }
    assert!(crossing_seen, "the byte bound seals during the run");
}

// PRJ-05
#[test]
#[expect(clippy::expect_used)]
fn one_block_over_the_byte_bound_is_sealed_alone() {
    const OVERSIZED: u32 = 3;
    const OVERSIZED_OUTPUTS: u32 = 230_000;
    let dir = tempfile::tempdir().expect("dir");
    let scratch = tempfile::tempdir().expect("scratch");
    let store =
        std::sync::Arc::new(bitcoin_rs_storage::RocksDbStore::open(dir.path()).expect("store"));
    let mut writer = crate::IndexWriter::open(std::sync::Arc::clone(&store), 1)
        .expect("writer")
        .with_seal_scratch(scratch.path().to_path_buf());
    let mut previous = [0u8; 32];
    for height in 0..OVERSIZED {
        let block = dense_block(height, previous, 16);
        previous = block.hash;
        commit_one(&mut writer, &block);
    }
    let big = dense_block(OVERSIZED, previous, OVERSIZED_OUTPUTS);
    commit_one(&mut writer, &big);

    let state = tail_state(store.as_ref());
    assert!(
        state.window.is_empty(),
        "the oversized block leaves the tail unchanged"
    );
    let sealed = state.newest().expect("the oversized block is sealed");
    assert_eq!(sealed.coverage.first_height, OVERSIZED);
    assert_eq!(sealed.coverage.last_height, OVERSIZED);
    assert_eq!(
        state.sealed.len(),
        2,
        "the prefix and the oversized block seal apart"
    );

    let next = dense_block(OVERSIZED + 1, big.hash, 16);
    commit_one(&mut writer, &next);
    let state = tail_state(store.as_ref());
    assert_eq!(state.first_height(), Some(OVERSIZED + 1));
    assert_eq!(
        state.newest().map(|sealed| sealed.coverage.last_height),
        Some(OVERSIZED)
    );
}

// PRJ-05
#[test]
#[expect(clippy::expect_used)]
fn oversized_crash_before_its_seal_is_sealed_before_the_next_append() {
    use crate::segment::{SealFault, arm_seal_fault};
    use bitcoin_rs_storage::KvStore as _;
    const OVERSIZED_OUTPUTS: u32 = 230_000;
    let dir = tempfile::tempdir().expect("dir");
    let scratch = tempfile::tempdir().expect("scratch");
    let store =
        std::sync::Arc::new(bitcoin_rs_storage::RocksDbStore::open(dir.path()).expect("store"));
    let oversized = dense_block(0, [0u8; 32], OVERSIZED_OUTPUTS);
    {
        let mut writer = crate::IndexWriter::open(std::sync::Arc::clone(&store), 1)
            .expect("writer")
            .with_seal_scratch(scratch.path().to_path_buf());
        arm_seal_fault(Some(SealFault::AfterStaging));
        let outcome = try_commit_one(&mut writer, &oversized);
        arm_seal_fault(None);
        assert!(
            outcome.is_err(),
            "the injected fault interrupts the seal that follows the commit"
        );
    }
    assert!(
        !tail_state(store.as_ref()).admits(0, 0),
        "the crash leaves the oversized block in the tail, over the bound"
    );

    let mut writer = crate::IndexWriter::open(std::sync::Arc::clone(&store), 1)
        .expect("writer")
        .with_seal_scratch(scratch.path().to_path_buf());
    writer
        .restore_tail_bounds()
        .expect("restart seals an over-bound tail");
    let restored = tail_state(store.as_ref());
    assert!(
        restored.admits(0, 0),
        "the restart leaves the tail within both bounds"
    );
    assert!(
        restored.window.is_empty(),
        "the restart seals the oversized block alone"
    );
    assert_eq!(
        restored.newest().map(|sealed| sealed.coverage.last_height),
        Some(0)
    );
    let next = dense_block(1, oversized.hash, 16);
    commit_one(&mut writer, &next);
    assert_eq!(tail_state(store.as_ref()).first_height(), Some(1));

    let blocks = [oversized, next];
    let bulk_dir = tempfile::tempdir().expect("bulk dir");
    let bulk_scratch = tempfile::tempdir().expect("bulk scratch");
    let bulk = std::sync::Arc::new(
        bitcoin_rs_storage::RocksDbStore::open(bulk_dir.path()).expect("bulk store"),
    );
    let coverage = crate::segment::bulk_builder::BulkSegmentBuilder::new(
        std::sync::Arc::new(bitcoin_rs_storage::budget::UnboundedBudget),
        None,
        bulk_scratch.path().to_path_buf(),
    )
    .build_and_ingest(bulk.as_ref(), 1, &blocks)
    .map_err(|error| error.to_string())
    .expect("bulk build");
    crate::segment::publish_sealed(
        bulk.as_ref(),
        1,
        coverage,
        2,
        crate::IndexCapabilities::HISTORICAL,
    )
    .expect("publish bulk");
    let live_view =
        crate::segment::read::SegmentSnapshot::open(store.snapshot().expect("live snapshot"))
            .expect("live view");
    let bulk_view =
        crate::segment::read::SegmentSnapshot::open(bulk.snapshot().expect("bulk snapshot"))
            .expect("bulk view");
    for block in &blocks {
        let hash = crate::ScriptHash::from_script_bytes(&block.txs[0].outputs[0].script);
        assert_eq!(
            live_view
                .history_answer_for_test(hash)
                .expect("live history"),
            bulk_view
                .history_answer_for_test(hash)
                .expect("bulk history"),
            "restored reads equal the bulk build at height {}",
            block.height
        );
    }
}

fn try_commit_one<S: bitcoin_rs_storage::KvStore>(
    writer: &mut crate::IndexWriter<S>,
    block: &bitcoin_rs_storage::CommittedBlock,
) -> Result<(), crate::IndexError> {
    let prepared = writer.prepare_block_from_facts(crate::IndexCapabilities::ALL, block)?;
    let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
        max_rows: usize::MAX,
        max_bytes: usize::MAX,
    });
    batch
        .try_push(prepared)
        .map_err(|_| crate::IndexError::NonContiguousPrepared { watermark: None })?;
    writer.commit_forward(batch).map(|_| ())
}

// PRJ-05
#[test]
#[expect(clippy::expect_used)]
fn block_tail_bound_covers_the_bytes_the_append_records() {
    use crate::segment::tail::{
        NoSealedTxOrdinals, TailWriterState, append_tail_block, block_tail_bytes_bound,
    };
    use bitcoin_rs_storage::KvStore as _;
    let dir = tempfile::tempdir().expect("dir");
    let store = bitcoin_rs_storage::RocksDbStore::open(dir.path()).expect("store");
    let mut dense_state = TailWriterState::new();
    let mut previous = [0u8; 32];
    for height in 0..4 {
        let block = dense_block(height, previous, 3_000);
        previous = block.hash;
        let mut batch = store.new_batch();
        append_tail_block(&mut batch, &block, &mut dense_state, &NoSealedTxOrdinals)
            .expect("append");
        let recorded = dense_state.window.back().expect("appended").bytes;
        let bound = block_tail_bytes_bound(&block);
        assert!(
            bound >= recorded,
            "height {height}: bound {bound} < recorded {recorded}"
        );
        assert!(
            bound <= recorded + recorded / 10 + 64,
            "height {height}: bound {bound} far above recorded {recorded}"
        );
    }
    let mut shared_state = TailWriterState::new();
    for block in &shared_script_blocks(6) {
        let mut batch = store.new_batch();
        append_tail_block(&mut batch, block, &mut shared_state, &NoSealedTxOrdinals)
            .expect("append");
        let recorded = shared_state.window.back().expect("appended").bytes;
        let bound = block_tail_bytes_bound(block);
        assert!(
            bound >= recorded,
            "height {}: bound {bound} < recorded {recorded}",
            block.height
        );
    }
}

struct ChunkCounter<'a> {
    inner: Box<dyn bitcoin_rs_storage::KvSnapshot + 'a>,
    chunks: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl bitcoin_rs_storage::KvSnapshot for ChunkCounter<'_> {
    fn get(
        &self,
        cf: bitcoin_rs_storage::ColumnFamily,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
        self.inner.get(cf, key)
    }

    fn iter_prefix<'b>(
        &'b self,
        cf: bitcoin_rs_storage::ColumnFamily,
        prefix: &[u8],
    ) -> Result<bitcoin_rs_storage::KvIter<'b>, bitcoin_rs_storage::StorageError> {
        let chunks = std::sync::Arc::clone(&self.chunks);
        let rows = self.inner.iter_prefix(cf, prefix)?;
        Ok(Box::new(rows.inspect(move |row| {
            if cf == bitcoin_rs_storage::ColumnFamily::ScriptPost && row.is_ok() {
                chunks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        })))
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: bitcoin_rs_storage::ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: bitcoin_rs_storage::PrefixScanLimit,
    ) -> Result<bitcoin_rs_storage::PrefixScan, bitcoin_rs_storage::StorageError> {
        let scan = self
            .inner
            .scan_prefix_from_bounded(cf, prefix, start, limit)?;
        if cf == bitcoin_rs_storage::ColumnFamily::ScriptPost {
            self.chunks
                .fetch_add(scan.rows.len(), std::sync::atomic::Ordering::SeqCst);
        }
        Ok(scan)
    }
}

// PRJ-08, IDX-12
#[test]
fn history_pages_seek_from_cursor_across_segments() -> Result<(), Box<dyn std::error::Error>> {
    use crate::segment::import::{
        TxOccurrence, next_segment_id, put_segment, stage_segment, tx_lookup_segment,
    };
    use crate::segment::{Coverage, SegmentSnapshot};
    use crate::types::{ScriptHash, TxPosition};
    use crate::{IndexCapabilities, IndexCapability, TxIndexSnapshot};
    use bitcoin_rs_storage::{ColumnFamily, KvStore, PrefixScanLimit, RocksDbStore};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SEGMENT_TXS: u32 = 20_000;
    const PAGE_ROWS: usize = 25;
    let page_len = u32::try_from(PAGE_ROWS)?;
    let dir = tempfile::tempdir()?;
    let store = RocksDbStore::open(dir.path())?;
    let script = ScriptHash::from_script_bytes(b"seek script");
    let caps = IndexCapabilities::TX_LOOKUP.insert(IndexCapability::ScriptHistory);
    for segment in 0..2_u32 {
        let first = segment * SEGMENT_TXS + 1;
        let last = first + SEGMENT_TXS - 1;
        let occurrences: Vec<TxOccurrence> = (first..=last)
            .map(|height| {
                let mut txid = [0_u8; 32];
                txid[..4].copy_from_slice(&height.to_be_bytes());
                TxOccurrence {
                    txid,
                    height,
                    block_hash: [9; 32],
                    position: TxPosition::new(0, 10),
                }
            })
            .collect();
        let mut restored = tx_lookup_segment(occurrences, Coverage::new(first, last, [7; 32]), 0)?;
        let dict_row = (
            encode_script_dict_key(0, &script.to_byte_array()).to_vec(),
            encode_script_dict_value(0).to_vec(),
        );
        let items: Vec<PostingItem> = (0..SEGMENT_TXS)
            .map(|ordinal| PostingItem {
                delta_ordinal: u32::from(ordinal > 0),
                flags: POSTING_FLAG_FUNDING,
            })
            .collect();
        restored
            .families
            .push((ColumnFamily::ScriptDict, vec![dict_row]));
        restored
            .families
            .push((ColumnFamily::ScriptPost, chunk_postings(0, 0, items)));
        let gen_id = next_segment_id(&store)?;
        stage_segment(&store, gen_id, &restored, dir.path())?;
        let mut batch = store.new_batch();
        put_segment(&mut batch, gen_id, &restored, caps);
        store.write_durable(batch)?;
    }

    let chunks = Arc::new(AtomicUsize::new(0));
    let snapshot = SegmentSnapshot::open(Box::new(ChunkCounter {
        inner: store.snapshot()?,
        chunks: Arc::clone(&chunks),
    }))?;
    let limit = |max_rows| PrefixScanLimit {
        max_rows,
        max_bytes: usize::MAX,
    };
    type Page = (Vec<u32>, usize);
    let read_page = |start: u32, max_rows: usize| -> Result<Page, Box<dyn std::error::Error>> {
        chunks.store(0, Ordering::SeqCst);
        let scan = snapshot.funding_rows_from(script, start, limit(max_rows))?;
        let heights = scan.rows.iter().map(|row| row.row.height()).collect();
        Ok((heights, chunks.load(Ordering::SeqCst)))
    };
    let page_from = |start: u32| -> Vec<u32> { (start + 1 - page_len..=start).rev().collect() };

    let top = 2 * SEGMENT_TXS;
    let (first_heights, first_chunks) = read_page(u32::MAX, PAGE_ROWS)?;
    assert_eq!(
        first_heights,
        page_from(top),
        "the first page starts at the tip"
    );
    assert!(
        first_chunks <= 2,
        "the first page read {first_chunks} chunks; the newest chunk alone fills it"
    );
    for cursor in [
        30,
        2_050,
        4_097,
        SEGMENT_TXS,
        SEGMENT_TXS + 1,
        15_000,
        35_000,
    ] {
        let (heights, chunks_read) = read_page(cursor, PAGE_ROWS)?;
        assert_eq!(heights, page_from(cursor), "the page after cursor {cursor}");
        assert!(
            chunks_read <= first_chunks + 1,
            "cursor {cursor} read {chunks_read} chunks; the first page read {first_chunks}"
        );
    }

    let mut walked = Vec::new();
    let mut start = u32::MAX;
    loop {
        let scan = snapshot.funding_rows_from(script, start, limit(1_000))?;
        walked.extend(scan.rows.iter().map(|row| row.row.height()));
        if scan.complete {
            break;
        }
        let Some(last) = scan.rows.last() else {
            return Err("a truncated page holds rows".into());
        };
        start = last.row.height().saturating_sub(1);
    }
    assert_eq!(walked, (1..=top).rev().collect::<Vec<u32>>());
    Ok(())
}
