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
                delta_ordinal: u32::from(chunk > 0),
                flags: POSTING_FLAG_FUNDING,
            };
            (
                encode_script_post_key(0, 0, chunk).to_vec(),
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
