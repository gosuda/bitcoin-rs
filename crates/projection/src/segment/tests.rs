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
