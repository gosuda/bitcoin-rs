pub mod bulk_builder;
pub mod format;
pub mod import;
mod read;
pub mod spill;
pub mod tail;
pub(crate) use read::{RecordPage, SegmentSnapshot};
pub use tail::{TailWriterState, append_tail_block};
#[cfg(test)]
mod tests {
    use super::format::*;

    fn publish_segment<S: bitcoin_rs_storage::KvStore>(
        store: &S,
        segment: &crate::segment::import::ImportedSegment,
        scratch: &std::path::Path,
        capabilities: crate::IndexCapabilities,
    ) -> Result<(), crate::IndexError> {
        let gen_id = crate::segment::import::next_segment_id(store)?;
        crate::segment::import::stage_segment(store, gen_id, segment, scratch)?;
        let mut batch = store.new_batch();
        crate::segment::import::put_segment(&mut batch, gen_id, segment, capabilities);
        store.write_durable(batch)?;
        Ok(())
    }

    // PRJ-08
    #[test]
    fn posting_holds_reference_and_flags_only() {
        let gen_id = 1u64;
        let script_id = 42u32;
        let chunk = 0u32;
        let key = encode_script_post_key(gen_id, script_id, chunk);

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
        assert_eq!(
            encoded.len(),
            items.len() * 2,
            "two bytes per posting: a one-byte ordinal varint and one flag byte"
        );
        assert!(
            encoded.len() < 32,
            "the posting value holds no script hash or txid"
        );
    }

    // PRJ-08, IDX-12
    #[test]
    fn history_pages_walk_more_than_256_posting_chunks() -> Result<(), crate::portable::TestError> {
        use crate::segment::import::{TxOccurrence, tx_lookup_segment};
        use crate::segment::{Coverage, SegmentSnapshot};
        use crate::types::{ScriptHash, TxPosition};
        use crate::{IndexCapabilities, IndexCapability, TxIndexSnapshot};
        use bitcoin_rs_storage::{ColumnFamily, KvStore, PrefixScanLimit, RocksDbStore};

        const TXS: u32 = 300;
        let dir = tempfile::tempdir()?;
        let store = RocksDbStore::open(dir.path())?;
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
        let mut segment = tx_lookup_segment(occurrences, coverage, 0)?;
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
        publish_segment(&store, &segment, dir.path(), caps)?;

        let snapshot = SegmentSnapshot::open(store.snapshot()?)?;
        let page_of = |max_rows| PrefixScanLimit {
            max_rows,
            max_bytes: usize::MAX,
        };
        let mut seen = Vec::new();
        let mut page = snapshot.funding_rows(script, page_of(7))?;
        loop {
            seen.extend(page.rows.iter().map(|row| row.row.height()));
            if page.complete {
                break;
            }
            let last = page
                .rows
                .last()
                .ok_or("a truncated page holds rows")?
                .row
                .height();
            page = snapshot.funding_rows_from(script, last.saturating_sub(1), page_of(7))?;
        }
        assert_eq!(seen, (1..=TXS).rev().collect::<Vec<u32>>());
        let unpaged = snapshot.funding_rows(script, page_of(usize::MAX))?;
        assert!(unpaged.complete);
        assert_eq!(unpaged.rows.len(), usize::try_from(TXS).unwrap_or(0));
        Ok(())
    }

    // PRJ-06
    #[test]
    fn rekeyed_sealed_generation_serves_its_script_history()
    -> Result<(), crate::portable::TestError> {
        use crate::segment::import::{TxOccurrence, tx_lookup_segment};
        use crate::segment::{Coverage, SegmentSnapshot};
        use crate::types::{ScriptHash, TxPosition};
        use crate::{IndexCapabilities, IndexCapability, TxIndexSnapshot};
        use bitcoin_rs_storage::{ColumnFamily, KvStore, PrefixScanLimit, RocksDbStore};

        let dir = tempfile::tempdir()?;
        let store = RocksDbStore::open(dir.path())?;
        let script = ScriptHash::from_script_bytes(b"rekeyed script");
        let dict_row = (
            encode_script_dict_key(0, &script.to_byte_array()).to_vec(),
            encode_script_dict_value(0).to_vec(),
        );
        let occurrence = |index: u32, height: u32| {
            let mut txid = [0_u8; 32];
            txid[..4].copy_from_slice(&index.to_be_bytes());
            TxOccurrence {
                txid,
                height,
                block_hash: [9_u8; 32],
                position: TxPosition::new(0, 10),
            }
        };
        let funding_postings = |ordinals: &[u32]| {
            ordinals
                .iter()
                .map(|&ordinal| {
                    (
                        encode_script_post_chunk_key(0, 0, ordinal).to_vec(),
                        encode_posting_items(&[PostingItem {
                            delta_ordinal: 0,
                            flags: POSTING_FLAG_FUNDING,
                        }]),
                    )
                })
                .collect::<Vec<_>>()
        };
        let seal = |occurrences: Vec<TxOccurrence>,
                    coverage: Coverage,
                    ordinal_base: u32,
                    chunk_ordinals: &[u32]|
         -> Result<(), crate::portable::TestError> {
            let mut segment = tx_lookup_segment(occurrences, coverage, ordinal_base)?;
            segment
                .families
                .push((ColumnFamily::ScriptDict, vec![dict_row.clone()]));
            segment
                .families
                .push((ColumnFamily::ScriptPost, funding_postings(chunk_ordinals)));
            let caps = IndexCapabilities::TX_LOOKUP.insert(IndexCapability::ScriptHistory);
            publish_segment(&store, &segment, dir.path(), caps)?;
            Ok(())
        };

        seal(
            vec![occurrence(0, 1), occurrence(1, 2)],
            Coverage::new(1, 2, [1_u8; 32]),
            0,
            &[0, 1],
        )?;
        seal(
            vec![occurrence(5, 11), occurrence(6, 12)],
            Coverage::new(11, 12, [2_u8; 32]),
            5,
            &[5, 6],
        )?;

        let snapshot = SegmentSnapshot::open(store.snapshot()?)?;
        let unlimited = PrefixScanLimit {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        };
        let scan = snapshot.funding_rows(script, unlimited)?;
        assert!(scan.complete);
        let heights: Vec<_> = scan.rows.iter().map(|row| row.row.height()).collect();
        assert_eq!(heights, [12, 11, 2, 1]);
        let rekeyed = crate::types::ScriptHistoryOccurrence::decode_all(&scan.rows[0].value)
            .ok_or("malformed occurrences")?;
        let mut expected_txid = [0_u8; 32];
        expected_txid[..4].copy_from_slice(&6_u32.to_be_bytes());
        assert_eq!(rekeyed.len(), 1);
        assert_eq!(rekeyed[0].txid, expected_txid);
        Ok(())
    }
    // IDX-10
    #[test]
    #[expect(clippy::expect_used)]
    fn restore_orphan_cleanup_deletes_only_the_pending_segment() {
        use super::{
            Coverage, SEAL_NEXT_GEN_KEY, SealedGen, encode_sealed_gen, retire_generation,
            retire_tombstone_key, sealed_gen_key,
        };
        use crate::segment::import::{
            FamilyRows, ImportedSegment, clear_unpublished_segment_rows, next_segment_id,
            put_segment, stage_segment,
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

        fn keyed(
            gen_id: u64,
            tag: u8,
            families: &[ColumnFamily],
        ) -> Vec<(ColumnFamily, FamilyRows)> {
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
        stage_segment(&store, pending, &pending_segment, dir.path())
            .expect("stage pending segment");

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

    // PRJ-12
    #[test]
    fn core_filter_vectors_read_back_through_the_segment_snapshot()
    -> Result<(), crate::portable::TestError> {
        use bitcoin::bip158::FilterHeader;
        use bitcoin::{consensus::deserialize, hashes::Hash as _, hex::FromHex as _};

        let vectors: Vec<sonic_rs::Value> = sonic_rs::from_str(include_str!(
            "../../../testdata/projection/data/blockfilters-core-31.1.json"
        ))?;
        let expected = vectors.len().saturating_sub(1);
        let mut compared = 0_usize;
        for vector in vectors.into_iter().skip(1) {
            let (height, _hash, body, prevouts, previous, expected_filter, expected_header, note): (
            u32,
            String,
            String,
            Vec<String>,
            String,
            String,
            String,
            String,
        ) = sonic_rs::from_value(&vector)?;
            let block: bitcoin::Block = deserialize(&Vec::from_hex(&body)?)?;
            let mut external = hashbrown::HashMap::new();
            for (input, script) in block
                .txdata
                .iter()
                .skip(1)
                .flat_map(|tx| &tx.input)
                .zip(prevouts)
            {
                external.insert(
                    (
                        input.previous_output.txid.to_byte_array(),
                        input.previous_output.vout,
                    ),
                    bitcoin_rs_storage::FactsScript::copy_from_slice(&Vec::from_hex(&script)?),
                );
            }
            let facts = committed_facts(&block, height, &external)?;
            let previous: FilterHeader = previous.parse()?;
            let filter = append_and_read(&facts, previous.to_byte_array())?;
            assert_eq!(filter.filter, Vec::from_hex(&expected_filter)?, "{note}");
            let expected: FilterHeader = expected_header.parse()?;
            assert_eq!(filter.header, expected.to_byte_array(), "{note}");
            compared += 1;
        }
        assert_eq!(compared, expected, "every fixture vector is compared");
        Ok(())
    }

    fn committed_facts(
        block: &bitcoin::Block,
        height: u32,
        external: &hashbrown::HashMap<([u8; 32], u32), bitcoin_rs_storage::FactsScript>,
    ) -> Result<bitcoin_rs_storage::CommittedBlock, crate::portable::TestError> {
        use bitcoin::hashes::Hash as _;
        use bitcoin_rs_storage::FactsScript;
        use bitcoin_rs_storage::committed_facts::{CreatedOutput, SpentPrevout, TxFacts};

        let mut created = hashbrown::HashMap::<([u8; 32], u32), FactsScript>::new();
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
                        script: FactsScript::default(),
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
                let script = FactsScript::copy_from_slice(out.script_pubkey.as_bytes());
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
        previous_header: [u8; 32],
    ) -> Result<crate::BasicFilter, crate::portable::TestError> {
        use crate::segment::SegmentSnapshot;
        use crate::segment::tail::{
            TailBounds, TailWriterState, append_tail_block, put_generation_descriptors,
        };
        use crate::{IndexCapability, TxIndexSnapshot};
        use bitcoin_rs_storage::{KvStore, RocksDbStore};

        let dir = tempfile::tempdir()?;
        let store = RocksDbStore::open(dir.path())?;
        let mut state = TailWriterState::new();
        state.prev_filter_header = previous_header;
        let mut batch = store.new_batch();
        append_tail_block(&mut batch, block, &mut state)?;
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
        let filter = append_and_read(&facts, [0; 32])?;
        let oracle = bitcoin::bip158::BlockFilter::new_script_filter(&block, |outpoint| {
            Err::<ScriptBuf, _>(bitcoin::bip158::Error::UtxoMissing(*outpoint))
        })?;
        assert_eq!(filter.filter, oracle.content);
        Ok(())
    }

    // PRJ-12
    #[test]
    fn same_block_spends_resolve_locally_and_empty_filters_encode_zero()
    -> Result<(), crate::portable::TestError> {
        use bitcoin::{
            Amount, OutPoint, ScriptBuf, TxOut, consensus::serialize, hashes::Hash as _,
        };

        struct NoSpentScripts;
        impl crate::SpentCoins for NoSpentScripts {
            fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<crate::SpentCoin<'_>> {
                None
            }
        }

        let mut block = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        block.txdata[0].output = vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
            },
        ];
        let empty = committed_facts(&block, 0, &hashbrown::HashMap::new())?;
        assert_eq!(append_and_read(&empty, [0; 32])?.filter, [0]);

        block.txdata[0].output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51]);
        let parent = block.txdata[0].compute_txid();
        let mut child = block.txdata[0].clone();
        child.input[0].previous_output = OutPoint {
            txid: parent,
            vout: 1,
        };
        child.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x52]);
        block.txdata.push(child);
        let mut same_block = committed_facts(&block, 1, &hashbrown::HashMap::new())?;
        same_block.txs[1].inputs[0].script = bitcoin_rs_storage::FactsScript::default();
        let filter = append_and_read(&same_block, [0; 32])?;
        let oracle = bitcoin::bip158::BlockFilter::new_script_filter(&block, |outpoint| {
            if *outpoint
                == (OutPoint {
                    txid: parent,
                    vout: 1,
                })
            {
                Ok(ScriptBuf::from_bytes(vec![0x6a]))
            } else {
                Err(bitcoin::bip158::Error::UtxoMissing(*outpoint))
            }
        })?;
        assert_eq!(filter.filter, oracle.content);
        assert_eq!(filter.filter.first().copied(), Some(3));

        block.txdata[1].input[0].previous_output.vout = 2;
        let image = crate::index::parse_body(&serialize(&block))?;
        let facts = crate::index::BodyFacts {
            height: 1,
            needs_scripts: true,
            spent_coins: &NoSpentScripts,
        };
        let result = crate::index::committed_block_from_image(
            &image,
            block.block_hash().to_byte_array(),
            [0; 32],
            &facts,
        );
        assert!(matches!(
            result,
            Err(crate::IndexError::MissingSpentCoin {
                height: 1,
                vout: 2,
                ..
            })
        ));
        Ok(())
    }

    fn shared_script_blocks(count: u32) -> Vec<bitcoin_rs_storage::CommittedBlock> {
        let script = bitcoin_rs_storage::FactsScript::copy_from_slice(&[0x51]);
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
            commit_from_facts(&mut writer, crate::IndexCapabilities::ALL, block).expect("commit");
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
        assert_eq!(
            live_history.len(),
            blocks.len(),
            "one history row per committed height"
        );
        assert_eq!(
            bulk_history.len(),
            blocks.len(),
            "the bulk build holds one history row per committed height"
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
                    script: bitcoin_rs_storage::FactsScript::copy_from_slice(&script),
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
    fn tail_state<S: bitcoin_rs_storage::KvStore>(
        store: &S,
    ) -> crate::segment::tail::TailWriterState {
        let snapshot = store.snapshot().expect("snapshot");
        crate::segment::tail::load(snapshot.as_ref()).expect("tail state")
    }
    fn commit_from_facts<S: bitcoin_rs_storage::KvStore>(
        writer: &mut crate::IndexWriter<S>,
        capabilities: crate::IndexCapabilities,
        block: &bitcoin_rs_storage::CommittedBlock,
    ) -> Result<(), crate::IndexError> {
        let prepared = writer.prepare_block_from_facts(capabilities, block.clone())?;
        let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        batch
            .try_push(prepared)
            .map_err(|_| crate::IndexError::NonContiguousPrepared { watermark: None })?;
        writer.commit_forward(batch).map(|_| ())
    }

    #[expect(clippy::expect_used)]
    fn commit_one<S: bitcoin_rs_storage::KvStore>(
        writer: &mut crate::IndexWriter<S>,
        block: &bitcoin_rs_storage::CommittedBlock,
    ) {
        commit_from_facts(writer, crate::IndexCapabilities::ALL, block).expect("commit");
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
            let outcome = commit_from_facts(&mut writer, crate::IndexCapabilities::ALL, &oversized);
            arm_seal_fault(None);
            assert!(
                matches!(
                    outcome,
                    Err(crate::IndexError::InjectedFault { stage: "seal" })
                ),
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

    // PRJ-05
    #[test]
    #[expect(clippy::expect_used)]
    fn block_tail_bound_covers_the_bytes_the_append_records() {
        use crate::segment::tail::{TailWriterState, append_tail_block, block_tail_bytes_bound};
        use bitcoin_rs_storage::KvStore as _;
        let dir = tempfile::tempdir().expect("dir");
        let store = bitcoin_rs_storage::RocksDbStore::open(dir.path()).expect("store");
        let mut dense_state = TailWriterState::new();
        let mut previous = [0u8; 32];
        for height in 0..4 {
            let block = dense_block(height, previous, 3_000);
            previous = block.hash;
            let mut batch = store.new_batch();
            append_tail_block(&mut batch, &block, &mut dense_state).expect("append");
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
            append_tail_block(&mut batch, block, &mut shared_state).expect("append");
            let recorded = shared_state.window.back().expect("appended").bytes;
            let bound = block_tail_bytes_bound(block);
            assert!(
                bound >= recorded,
                "height {}: bound {bound} < recorded {recorded}",
                block.height
            );
        }
    }

    fn fund_and_spend_blocks(
        outputs: u32,
        script: &[u8],
    ) -> [bitcoin_rs_storage::CommittedBlock; 2] {
        use bitcoin_rs_storage::FactsScript;
        use bitcoin_rs_storage::committed_facts::{CreatedOutput, SpentPrevout, TxFacts};
        let funding_txid = [0xD0; 32];
        let fund = bitcoin_rs_storage::CommittedBlock {
            height: 1,
            hash: [0x81; 32],
            parent_hash: [0; 32],
            header: [0; 80],
            txs: vec![TxFacts {
                txid: funding_txid,
                offset: 0,
                len: 120,
                inputs: Vec::new(),
                outputs: (0..outputs)
                    .map(|vout| CreatedOutput {
                        vout,
                        value: 1,
                        script: FactsScript::copy_from_slice(script),
                    })
                    .collect(),
            }],
        };
        let spend = bitcoin_rs_storage::CommittedBlock {
            height: 2,
            hash: [0x82; 32],
            parent_hash: fund.hash,
            header: [0; 80],
            txs: vec![TxFacts {
                txid: [0xD1; 32],
                offset: 0,
                len: 120,
                inputs: (0..outputs)
                    .map(|vout| SpentPrevout {
                        txid: funding_txid,
                        vout,
                        value: 1,
                        script: FactsScript::copy_from_slice(script),
                        height: 1,
                        coinbase: false,
                    })
                    .collect(),
                outputs: Vec::new(),
            }],
        };
        [fund, spend]
    }

    // PRJ-05
    #[test]
    #[expect(clippy::expect_used)]
    fn block_tail_bound_counts_empty_script_occurrences() {
        use crate::segment::tail::{TailWriterState, append_tail_block, block_tail_bytes_bound};
        use bitcoin_rs_storage::KvStore as _;
        let dir = tempfile::tempdir().expect("dir");
        let store = bitcoin_rs_storage::RocksDbStore::open(dir.path()).expect("store");
        let mut state = TailWriterState::new();
        let empty_script = fund_and_spend_blocks(64, &[]);
        let shared_script = fund_and_spend_blocks(64, &[0x51]);
        for (block, same_shape) in empty_script.iter().zip(&shared_script) {
            let mut batch = store.new_batch();
            append_tail_block(&mut batch, block, &mut state).expect("append");
            let recorded = state.window.back().expect("appended").bytes;
            let bound = block_tail_bytes_bound(block);
            assert!(
                bound >= recorded,
                "height {}: bound {bound} < recorded {recorded}",
                block.height
            );
            assert_eq!(
                bound,
                block_tail_bytes_bound(same_shape),
                "height {}: an empty script costs what any other script costs",
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

    #[derive(Debug, thiserror::Error)]
    enum PageTestError {
        #[error(transparent)]
        Index(#[from] crate::IndexError),
        #[error(transparent)]
        Storage(#[from] bitcoin_rs_storage::StorageError),
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        Integer(#[from] std::num::TryFromIntError),
        #[error("a truncated page holds rows")]
        EmptyTruncatedPage,
    }

    // PRJ-08, IDX-12
    #[test]
    fn history_pages_seek_from_cursor_across_segments() -> Result<(), PageTestError> {
        use crate::segment::import::{TxOccurrence, tx_lookup_segment};
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
            let mut restored =
                tx_lookup_segment(occurrences, Coverage::new(first, last, [7; 32]), 0)?;
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
            publish_segment(&store, &restored, dir.path(), caps)?;
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
        let read_page = |start: u32, max_rows: usize| -> Result<Page, PageTestError> {
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
            first_chunks >= 1,
            "the first page reads at least one posting chunk"
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
                return Err(PageTestError::EmptyTruncatedPage);
            };
            start = last.row.height().saturating_sub(1);
        }
        assert_eq!(walked, (1..=top).rev().collect::<Vec<u32>>());
        Ok(())
    }
    // PRJ-05
    #[test]
    #[expect(clippy::expect_used)]
    fn compact_filters_only_restart_resumes_past_the_sealed_filters() {
        use bitcoin_rs_storage::{ColumnFamily, KvStore as _};
        let blocks = shared_script_blocks(2);
        let dir = tempfile::tempdir().expect("dir");
        let scratch = tempfile::tempdir().expect("scratch");
        let store =
            std::sync::Arc::new(bitcoin_rs_storage::RocksDbStore::open(dir.path()).expect("store"));
        let mut writer =
            crate::IndexWriter::open(std::sync::Arc::clone(&store), 1).expect("writer");
        for block in &blocks {
            commit_from_facts(
                &mut writer,
                crate::IndexCapabilities::COMPACT_FILTERS,
                block,
            )
            .expect("commit");
        }
        super::seal_tail_generation(
            store.as_ref(),
            1,
            1,
            crate::IndexCapabilities::COMPACT_FILTERS,
            scratch.path(),
        )
        .expect("seal");
        let snapshot = store.snapshot().expect("snapshot");
        let sealed =
            super::sealed_generations(snapshot.as_ref(), crate::IndexCapability::CompactFilters)
                .expect("sealed scan");
        let newest = sealed.last().expect("one sealed generation");
        assert_eq!(newest.gen_id, 1, "the seal lands under compact_filters");
        let sealed_row = snapshot
            .get(
                ColumnFamily::Filters,
                &encode_filter_key(newest.gen_id, newest.coverage.last_height),
            )
            .expect("read sealed filter")
            .expect("sealed filter row");
        let (_, _, sealed_header, _) =
            decode_filter_value(&sealed_row).expect("decode sealed filter");
        assert_eq!(
            super::tail::next_gen_id(snapshot.as_ref()).expect("next id"),
            newest.gen_id.saturating_add(1),
            "the next generation advances past the sealed filters"
        );
        drop(snapshot);
        let state = tail_state(store.as_ref());
        assert_eq!(
            state.next_gen_id,
            newest.gen_id.saturating_add(1),
            "the reopened writer seals the next generation"
        );
        assert_eq!(
            state.at,
            Some((newest.coverage.last_height, newest.coverage.last_hash)),
            "the tip resumes at the sealed filters"
        );
        assert_eq!(
            state.prev_filter_header, sealed_header,
            "the next filter chains from the sealed header"
        );
    }

    // PRJ-03, PRJ-05, REO-04
    #[test]
    #[expect(clippy::expect_used)]
    fn lagging_filters_seal_full_transaction_tail_without_losing_its_owner() {
        use super::read::SegmentSnapshot;
        use bitcoin_rs_consensus::primitives::{Hash256, Txid};
        use bitcoin_rs_storage::KvStore as _;

        for fault in [
            None,
            Some(super::SealFault::AfterIngest),
            Some(super::SealFault::AfterCommitted),
        ] {
            let mut blocks = shared_script_blocks(TAIL_MAX_BLOCKS);
            blocks[0].txs[0].txid = [0xa7; 32];
            let dir = tempfile::tempdir().expect("dir");
            let scratch = tempfile::tempdir().expect("scratch");
            let store = std::sync::Arc::new(
                bitcoin_rs_storage::RocksDbStore::open(dir.path()).expect("store"),
            );
            let mut writer = crate::IndexWriter::open(std::sync::Arc::clone(&store), 1)
                .expect("writer")
                .with_seal_scratch(scratch.path().to_path_buf());
            for block in &blocks {
                commit_from_facts(&mut writer, crate::IndexCapabilities::TX_LOOKUP, block)
                    .expect("commit transaction");
            }
            let before = writer.watermarks().expect("watermarks");
            assert!(before.compact_filters.is_none());
            assert_eq!(
                tail_state(store.as_ref()).window.len(),
                usize::try_from(TAIL_MAX_BLOCKS).expect("block bound")
            );
            super::arm_seal_fault(fault);
            let result = commit_from_facts(
                &mut writer,
                crate::IndexCapabilities::COMPACT_FILTERS,
                &blocks[0],
            );
            super::arm_seal_fault(None);
            if fault.is_some() {
                assert!(matches!(
                    result,
                    Err(crate::IndexError::InjectedFault { stage: "seal" })
                ));
                drop(writer);
                super::recover_segments(store.as_ref()).expect("recover seal");
                writer = crate::IndexWriter::open(std::sync::Arc::clone(&store), 1)
                    .expect("reopen writer")
                    .with_seal_scratch(scratch.path().to_path_buf());
                assert_eq!(writer.watermarks().expect("recovered watermarks"), before);
                let view = SegmentSnapshot::open(store.snapshot().expect("snapshot"))
                    .expect("recovered view");
                let found = view
                    .tx_answer_for_test(&Txid(Hash256::from_le_bytes(&[0xa7; 32])))
                    .expect("transaction");
                assert_eq!(found.len(), 1);
                assert_eq!(found[0].0, 0);
                drop(view);
                commit_from_facts(
                    &mut writer,
                    crate::IndexCapabilities::COMPACT_FILTERS,
                    &blocks[0],
                )
                .expect("retry filter");
            } else {
                result.expect("commit filter");
            }
            let after = writer.watermarks().expect("watermarks after filter");
            assert_eq!(after.tx_lookup, before.tx_lookup);
            assert_eq!(after.script_history, None);
            assert_eq!(after.script_live, None);
            assert_eq!(
                after.compact_filters,
                Some(crate::IndexWatermark {
                    height: 0,
                    hash: blocks[0].hash
                })
            );
            let view = SegmentSnapshot::open(store.snapshot().expect("snapshot")).expect("view");
            let found = view
                .tx_answer_for_test(&Txid(Hash256::from_le_bytes(&[0xa7; 32])))
                .expect("transaction");
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].0, 0);
        }
    }
    // PRJ-05
    #[test]
    #[expect(clippy::expect_used)]
    fn script_stats_rows_count_toward_the_tail_byte_budget() {
        use super::tail::{TailWriterState, append_tail_block};
        use bitcoin_rs_storage::{BatchOp, BufferedWriteBatch, ColumnFamily};
        let block = dense_block(0, [0u8; 32], 8);
        let mut state = TailWriterState::new();
        let mut batch = BufferedWriteBatch::default();
        append_tail_block(&mut batch, &block, &mut state).expect("append");
        let recorded = state.window.back().expect("appended").bytes;
        let mut row_bytes = 0_u64;
        let mut stats_rows = 0_u64;
        let mut log_len = 0_u64;
        for op in batch.into_ops() {
            let BatchOp::Put { cf, key, value } = op else {
                continue;
            };
            if cf == ColumnFamily::IdxMeta {
                log_len = u64::try_from(value.len()).expect("log len fits");
                continue;
            }
            row_bytes = row_bytes
                .saturating_add(u64::try_from(key.len()).expect("key len fits"))
                .saturating_add(u64::try_from(value.len()).expect("value len fits"));
            if cf == ColumnFamily::ScriptStats {
                stats_rows = stats_rows.saturating_add(1);
                assert_eq!(
                    key.len(),
                    SCRIPT_STATS_KEY_LEN,
                    "stats key holds gen and script"
                );
                assert_eq!(
                    value.len(),
                    SCRIPT_STATS_VALUE_LEN,
                    "stats value holds counts and sats"
                );
            }
        }
        assert_eq!(stats_rows, 8, "one stats row per funded script occurrence");
        assert!(
            recorded >= row_bytes.saturating_add(log_len),
            "recorded {recorded} covers {row_bytes} row bytes plus {log_len} log bytes"
        );
        let bound = u64::try_from(TAIL_MAX_BYTES).expect("bound fits");
        let room = bound.saturating_sub(row_bytes).saturating_sub(log_len);
        assert!(
            !state.admits(0, room.saturating_add(1)),
            "the tail refuses the first byte past the recorded cost"
        );
        assert!(
            state.admits(0, room.saturating_sub(512)),
            "the tail admits bytes inside the recorded cost"
        );
    }
    // PRJ-05
    #[test]
    #[expect(clippy::expect_used)]
    fn tail_resume_chains_onto_the_newest_durable_filter_row() {
        use bitcoin_rs_storage::{ColumnFamily, KvStore as _};
        let blocks = shared_script_blocks(4);
        let dir = tempfile::tempdir().expect("dir");
        let scratch = tempfile::tempdir().expect("scratch");
        let store =
            std::sync::Arc::new(bitcoin_rs_storage::RocksDbStore::open(dir.path()).expect("store"));
        let mut writer =
            crate::IndexWriter::open(std::sync::Arc::clone(&store), 1).expect("writer");
        for (height, block) in blocks.iter().enumerate() {
            let capabilities = if height < 2 {
                crate::IndexCapabilities::TX_LOOKUP.with_compact_filters(true)
            } else {
                crate::IndexCapabilities::TX_LOOKUP
            };
            commit_from_facts(&mut writer, capabilities, block).expect("commit");
        }
        super::seal_tail_generation(
            store.as_ref(),
            1,
            1,
            crate::IndexCapabilities::TX_LOOKUP.with_compact_filters(true),
            scratch.path(),
        )
        .expect("seal the filter chain into generation 1");
        super::seal_tail_generation(
            store.as_ref(),
            2,
            3,
            crate::IndexCapabilities::TX_LOOKUP,
            scratch.path(),
        )
        .expect("seal generation 2 without filters");
        let snapshot = store.snapshot().expect("snapshot");
        let sealed_row = snapshot
            .get(ColumnFamily::Filters, &encode_filter_key(1, 1))
            .expect("read the sealed filter row")
            .expect("generation 1 holds the filter chain");
        let (_, _, chain_header, _) =
            decode_filter_value(&sealed_row).expect("decode sealed filter");
        let state = tail_state(store.as_ref());
        assert_eq!(
            state.prev_filter_header, chain_header,
            "the resumed tail chains onto the newest durable filter row"
        );
    }

    // PRJ-06, PRJ-07
    #[test]
    fn spends_after_seal_preserve_repeated_outpoint_events()
    -> Result<(), crate::portable::TestError> {
        use super::seal_tail_generation;
        use super::tail::{TailWriterState, append_tail_block};
        use crate::TxIndexSnapshot;
        use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid};
        use bitcoin_rs_storage::committed_facts::{
            CommittedBlock, CreatedOutput, SpentPrevout, TxFacts,
        };
        use bitcoin_rs_storage::{ColumnFamily, FactsScript, KvStore, RocksDbStore};

        let dir = tempfile::tempdir()?;
        let scratch = tempfile::tempdir()?;
        let store = RocksDbStore::open(dir.path())?;
        let txid = [0x5a; 32];
        let script = FactsScript::copy_from_slice(b"\x51creator");
        let creations: Vec<_> = (1_u8..=2)
            .map(|height| CommittedBlock {
                height: u32::from(height),
                hash: [height; 32],
                parent_hash: [height - 1; 32],
                header: [0; 80],
                txs: vec![TxFacts {
                    txid,
                    offset: 0,
                    len: 100,
                    inputs: Vec::new(),
                    outputs: vec![CreatedOutput {
                        vout: 0,
                        value: 5_000,
                        script: script.clone(),
                    }],
                }],
            })
            .collect();
        let spending_ordinal = u32::try_from(creations.iter().map(|b| b.txs.len()).sum::<usize>())?;
        let mut state = TailWriterState::new();
        for block in &creations {
            let mut batch = store.new_batch();
            append_tail_block(&mut batch, block, &mut state)?;
            store.write_durable(batch)?;
        }
        let gen_id = 4;
        seal_tail_generation(
            &store,
            gen_id,
            2,
            crate::IndexCapabilities::SCRIPT_HISTORY,
            scratch.path(),
        )?;
        let spending = CommittedBlock {
            height: 3,
            hash: [3; 32],
            parent_hash: [2; 32],
            header: [0; 80],
            txs: vec![TxFacts {
                txid: [0xb2; 32],
                offset: 100,
                len: 120,
                inputs: vec![SpentPrevout {
                    txid,
                    vout: 0,
                    value: 5_000,
                    script,
                    height: 2,
                    coinbase: false,
                }],
                outputs: Vec::new(),
            }],
        };
        let mut state = TailWriterState::new();
        state.next_ordinal = spending_ordinal;
        let mut batch = store.new_batch();
        append_tail_block(&mut batch, &spending, &mut state)?;
        store.write_durable(batch)?;
        let mut recreated = creations[1].clone();
        recreated.height = spending.height + 1;
        recreated.hash = [4; 32];
        recreated.parent_hash = spending.hash;
        let mut batch = store.new_batch();
        append_tail_block(&mut batch, &recreated, &mut state)?;
        store.write_durable(batch)?;
        let mut repeated = spending.clone();
        repeated.height = recreated.height + 1;
        repeated.hash = [5; 32];
        repeated.parent_hash = recreated.hash;
        repeated.txs[0].txid = [0xb3; 32];
        repeated.txs[0].inputs[0].height = recreated.height;
        repeated.txs[0].offset = 200;
        repeated.txs[0].len = 140;
        let mut batch = store.new_batch();
        append_tail_block(&mut batch, &repeated, &mut state)?;
        store.write_durable(batch)?;
        let spends: Vec<_> = store
            .iter_prefix(ColumnFamily::SpendDir, &0_u64.to_be_bytes())?
            .map(|row| {
                let (key, _) = row?;
                Ok(decode_spend_dir_key(&key))
            })
            .collect::<Result<_, bitcoin_rs_storage::StorageError>>()?;
        let input = &spending.txs[0].inputs[0];
        assert_eq!(
            spends,
            vec![
                Some((0, input.txid, input.vout, spending.height)),
                Some((0, input.txid, input.vout, repeated.height)),
            ],
            "each spending height retains its own event for the exact repeated outpoint"
        );
        seal_tail_generation(
            &store,
            gen_id + 1,
            repeated.height,
            crate::IndexCapabilities::SCRIPT_HISTORY,
            scratch.path(),
        )?;
        let view = super::SegmentSnapshot::open(store.snapshot()?)?;
        let answer = view.spending_rows(
            &OutPoint {
                txid: Txid::from(Hash256::from_le_bytes(&input.txid)),
                vout: input.vout,
            },
            bitcoin_rs_storage::PrefixScanLimit {
                max_rows: 16,
                max_bytes: 1 << 20,
            },
        )?;
        assert!(answer.complete);
        let actual = answer
            .rows
            .iter()
            .map(|row| {
                let positions = crate::TxPositionValue::decode(&row.value)
                    .ok_or("spender positions must decode")?;
                Ok((
                    row.row.height(),
                    positions
                        .iter()
                        .map(|p| (p.offset(), p.byte_len()))
                        .collect::<Vec<_>>(),
                ))
            })
            .collect::<Result<Vec<_>, crate::portable::TestError>>()?;
        assert_eq!(
            actual,
            vec![
                (
                    spending.height,
                    vec![(spending.txs[0].offset, spending.txs[0].len)]
                ),
                (
                    repeated.height,
                    vec![(repeated.txs[0].offset, repeated.txs[0].len)]
                ),
            ],
            "public spender lookup retains both historical events, not only the latest one"
        );
        Ok(())
    }

    // IDX-12
    #[test]
    fn positive_floor_bulk_and_tail_preserve_spends_without_indexed_funding()
    -> Result<(), crate::portable::TestError> {
        use crate::{IndexReader, TxPositionValue};
        use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid};
        use bitcoin_rs_storage::{PrefixScanLimit, RocksDbStore};

        let [funding, spending] = fund_and_spend_blocks(1, &[0x51]);
        let input = &spending.txs[0].inputs[0];
        assert!(input.height < spending.height);
        assert_eq!(input.txid, funding.txs[0].txid);
        let outpoint = OutPoint {
            txid: Txid::from(Hash256::from_le_bytes(&input.txid)),
            vout: input.vout,
        };
        let limit = PrefixScanLimit {
            max_rows: 16,
            max_bytes: 1 << 20,
        };
        for bulk in [false, true] {
            let dir = tempfile::tempdir()?;
            let scratch = tempfile::tempdir()?;
            let store = std::sync::Arc::new(RocksDbStore::open(dir.path())?);
            if bulk {
                let builder = super::bulk_builder::BulkSegmentBuilder::new(
                    std::sync::Arc::new(bitcoin_rs_storage::budget::UnboundedBudget),
                    None,
                    scratch.path().to_path_buf(),
                );
                let coverage = builder
                    .build_and_ingest(store.as_ref(), 1, std::slice::from_ref(&spending))
                    .map_err(std::io::Error::other)?;
                super::publish_sealed(
                    store.as_ref(),
                    1,
                    coverage,
                    1,
                    crate::IndexCapabilities::HISTORICAL,
                )?;
            } else {
                let mut writer = crate::IndexWriter::open(std::sync::Arc::clone(&store), 1)?;
                writer.anchor_watermark(
                    crate::IndexCapabilities::HISTORICAL,
                    crate::IndexWatermark {
                        height: spending.height - 1,
                        hash: spending.parent_hash,
                    },
                    spending.height,
                )?;
                commit_from_facts(&mut writer, crate::IndexCapabilities::HISTORICAL, &spending)?;
            }
            let indexer = crate::Indexer::new(std::sync::Arc::clone(&store));
            let view = indexer.snapshot()?;
            assert!(
                view.transaction_rows(&outpoint.txid, limit)?
                    .rows
                    .is_empty(),
                "funding below coverage must not acquire a synthetic transaction"
            );
            let unrelated = OutPoint {
                vout: 1,
                ..outpoint
            };
            assert!(view.spending_rows(&unrelated, limit)?.rows.is_empty());
            let answer = view.spending_rows(&outpoint, limit)?;
            assert!(answer.complete);
            assert_eq!(
                answer.rows.len(),
                1,
                "bulk={bulk}: the covered input spends an exact outpoint created below the floor"
            );
            assert_eq!(answer.rows[0].row.height(), spending.height);
            let positions = TxPositionValue::decode(&answer.rows[0].value)
                .ok_or("spender positions must decode")?;
            assert_eq!(
                positions
                    .iter()
                    .map(|p| (p.offset(), p.byte_len()))
                    .collect::<Vec<_>>(),
                vec![(spending.txs[0].offset, spending.txs[0].len)]
            );
        }
        Ok(())
    }
}

use crate::{IndexCapabilities, IndexCapability};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coverage {
    pub first_height: u32,
    pub last_height: u32,
    pub last_hash: [u8; 32],
}

impl Coverage {
    #[must_use]
    pub const fn new(first_height: u32, last_height: u32, last_hash: [u8; 32]) -> Self {
        Self {
            first_height,
            last_height,
            last_hash,
        }
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[0..4].copy_from_slice(&self.first_height.to_le_bytes());
        out[4..8].copy_from_slice(&self.last_height.to_le_bytes());
        out[8..40].copy_from_slice(&self.last_hash);
        out
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 40 {
            return None;
        }
        let first_height = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        let last_height = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        let mut last_hash = [0u8; 32];
        last_hash.copy_from_slice(&bytes[8..40]);
        Some(Self {
            first_height,
            last_height,
            last_hash,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TailDescriptor {
    pub tail_lo: u32,
    pub tail_hi: u32,
    pub tail_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerationDescriptor {
    pub gen_id: u64,
    pub coverage: Coverage,
    pub tail: TailDescriptor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentRef {
    pub gen_id: u64,
    pub capability: IndexCapability,
    pub coverage: Coverage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexGeneration {
    pub id: u64,
    pub segments: [Option<SegmentRef>; 4],
    pub tail: TailDescriptor,
}

impl IndexGeneration {
    pub const VALUE_LEN: usize = 88;

    #[must_use]
    pub fn encode_meta_value(desc: &GenerationDescriptor) -> [u8; Self::VALUE_LEN] {
        let mut out = [0u8; Self::VALUE_LEN];
        out[0..8].copy_from_slice(&desc.gen_id.to_le_bytes());
        out[8..48].copy_from_slice(&desc.coverage.to_bytes());
        out[48..52].copy_from_slice(&desc.tail.tail_lo.to_le_bytes());
        out[52..56].copy_from_slice(&desc.tail.tail_hi.to_le_bytes());
        out[56..88].copy_from_slice(&desc.tail.tail_hash);
        out
    }

    #[must_use]
    pub fn decode_meta_value(bytes: &[u8]) -> Option<GenerationDescriptor> {
        if bytes.len() < Self::VALUE_LEN {
            return None;
        }
        let gen_id = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let coverage = Coverage::from_bytes(&bytes[8..48])?;
        let tail_lo = u32::from_le_bytes(bytes[48..52].try_into().ok()?);
        let tail_hi = u32::from_le_bytes(bytes[52..56].try_into().ok()?);
        let mut tail_hash = [0u8; 32];
        tail_hash.copy_from_slice(&bytes[56..88]);
        Some(GenerationDescriptor {
            gen_id,
            coverage,
            tail: TailDescriptor {
                tail_lo,
                tail_hi,
                tail_hash,
            },
        })
    }
}

#[must_use]
pub fn meta_gen_key(capability: IndexCapability) -> Vec<u8> {
    let mut key = b"gen/".to_vec();
    key.extend_from_slice(capability.name().as_bytes());
    key
}

/// One sealed segment of a capability (`PRJ-05`): its coverage and the first
/// chain-global ordinal after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedGen {
    pub gen_id: u64,
    pub coverage: Coverage,
    pub next_ordinal: u32,
}

/// Length of a sealed segment record: coverage (40) plus next ordinal (4).
pub const SEALED_RECORD_LEN: usize = 44;

#[must_use]
pub fn sealed_gen_prefix(capability: IndexCapability) -> Vec<u8> {
    let mut key = b"gen/".to_vec();
    key.extend_from_slice(capability.name().as_bytes());
    key.push(b'/');
    key
}

#[must_use]
pub fn sealed_gen_key(capability: IndexCapability, gen_id: u64) -> Vec<u8> {
    let mut key = sealed_gen_prefix(capability);
    key.extend_from_slice(&gen_id.to_be_bytes());
    key
}

#[must_use]
pub fn encode_sealed_gen(sealed: &SealedGen) -> [u8; SEALED_RECORD_LEN] {
    let mut out = [0u8; SEALED_RECORD_LEN];
    out[..40].copy_from_slice(&sealed.coverage.to_bytes());
    out[40..44].copy_from_slice(&sealed.next_ordinal.to_le_bytes());
    out
}

fn decode_sealed_gen(gen_id: u64, bytes: &[u8]) -> Option<SealedGen> {
    if bytes.len() < SEALED_RECORD_LEN {
        return None;
    }
    Some(SealedGen {
        gen_id,
        coverage: Coverage::from_bytes(&bytes[..40])?,
        next_ordinal: u32::from_le_bytes(bytes[40..44].try_into().ok()?),
    })
}

/// Sealed segments of `capability`, ascending by generation id.
pub fn sealed_generations(
    snapshot: &dyn bitcoin_rs_storage::KvSnapshot,
    capability: IndexCapability,
) -> Result<Vec<SealedGen>, crate::IndexError> {
    let prefix = sealed_gen_prefix(capability);
    let mut out = Vec::new();
    for item in snapshot.iter_prefix(bitcoin_rs_storage::ColumnFamily::IdxMeta, &prefix)? {
        let (key, value) = item?;
        let Some(id_bytes) = key.get(prefix.len()..) else {
            continue;
        };
        let Ok(id_array) = <[u8; 8]>::try_from(id_bytes) else {
            continue;
        };
        if let Some(sealed) = decode_sealed_gen(u64::from_be_bytes(id_array), &value) {
            out.push(sealed);
        }
    }
    out.sort_unstable_by_key(|sealed| sealed.gen_id);
    Ok(out)
}

pub const SEAL_STAGING_KEY: &[u8] = b"seal/staging";
pub const SEAL_COMMITTED_KEY: &[u8] = b"seal/committed";
pub const SEAL_NEXT_GEN_KEY: &[u8] = b"seal/next_gen";

const RETIRE_TOMBSTONE_PREFIX: &[u8] = b"retire/";

const SEALED_FAMILIES: [bitcoin_rs_storage::ColumnFamily; 6] = [
    bitcoin_rs_storage::ColumnFamily::TxDir,
    bitcoin_rs_storage::ColumnFamily::ScriptDict,
    bitcoin_rs_storage::ColumnFamily::ScriptPost,
    bitcoin_rs_storage::ColumnFamily::SpendDir,
    bitcoin_rs_storage::ColumnFamily::ScriptStats,
    bitcoin_rs_storage::ColumnFamily::Filters,
];

/// Test-only fault injection points for the seal protocol; production code
/// never arms them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealFault {
    AfterStaging = 1,
    AfterIngest = 2,
    AfterCommitted = 3,
    AfterPublish = 4,
}

impl SealFault {
    const fn code(self) -> u8 {
        match self {
            Self::AfterStaging => 1,
            Self::AfterIngest => 2,
            Self::AfterCommitted => 3,
            Self::AfterPublish => 4,
        }
    }
}

/// Test-only fault injection points for the retire protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetireFault {
    AfterTombstone = 1,
    AfterClear = 2,
    AfterDescriptor = 3,
}

impl RetireFault {
    const fn code(self) -> u8 {
        match self {
            Self::AfterTombstone => 1,
            Self::AfterClear => 2,
            Self::AfterDescriptor => 3,
        }
    }
}

thread_local! {
    static SEAL_FAULT: core::cell::Cell<u8> = const { core::cell::Cell::new(0) };
    static RETIRE_FAULT: core::cell::Cell<u8> = const { core::cell::Cell::new(0) };
}

pub fn arm_seal_fault(fault: Option<SealFault>) {
    let value = fault.map_or(0, SealFault::code);
    SEAL_FAULT.with(|cell| cell.set(value));
}

pub fn arm_retire_fault(fault: Option<RetireFault>) {
    let value = fault.map_or(0, RetireFault::code);
    RETIRE_FAULT.with(|cell| cell.set(value));
}

fn seal_fault(stage: SealFault) -> Result<(), crate::IndexError> {
    if SEAL_FAULT.with(core::cell::Cell::get) == stage.code() {
        return Err(crate::IndexError::InjectedFault { stage: "seal" });
    }
    Ok(())
}

fn retire_fault(stage: RetireFault) -> Result<(), crate::IndexError> {
    if RETIRE_FAULT.with(core::cell::Cell::get) == stage.code() {
        return Err(crate::IndexError::InjectedFault { stage: "retire" });
    }
    Ok(())
}

const SEAL_MARKER_LEN: usize = 53;

fn seal_marker_value(
    gen_id: u64,
    coverage: &Coverage,
    capabilities: IndexCapabilities,
    next_ordinal: u32,
) -> [u8; SEAL_MARKER_LEN] {
    let mut out = [0u8; SEAL_MARKER_LEN];
    out[..8].copy_from_slice(&gen_id.to_le_bytes());
    out[8..48].copy_from_slice(&coverage.to_bytes());
    out[48] = capabilities.to_mask();
    out[49..53].copy_from_slice(&next_ordinal.to_le_bytes());
    out
}

fn decode_seal_marker(bytes: &[u8]) -> Option<(u64, Coverage, IndexCapabilities, u32)> {
    if bytes.len() < SEAL_MARKER_LEN {
        return None;
    }
    let gen_id = u64::from_le_bytes(bytes[..8].try_into().ok()?);
    let coverage = Coverage::from_bytes(&bytes[8..48])?;
    let capabilities = IndexCapabilities::from_mask(bytes[48]).ok()?;
    let next_ordinal = u32::from_le_bytes(bytes[49..53].try_into().ok()?);
    Some((gen_id, coverage, capabilities, next_ordinal))
}

fn retirement_families(capability: IndexCapability) -> &'static [bitcoin_rs_storage::ColumnFamily] {
    match capability {
        IndexCapability::TxLookup => &[bitcoin_rs_storage::ColumnFamily::TxDir],
        IndexCapability::ScriptHistory => &[
            bitcoin_rs_storage::ColumnFamily::ScriptDict,
            bitcoin_rs_storage::ColumnFamily::ScriptPost,
            bitcoin_rs_storage::ColumnFamily::SpendDir,
            bitcoin_rs_storage::ColumnFamily::ScriptStats,
        ],
        IndexCapability::ScriptLive => &[bitcoin_rs_storage::ColumnFamily::ScriptLive],
        IndexCapability::CompactFilters => &[bitcoin_rs_storage::ColumnFamily::Filters],
    }
}
fn retire_tombstone_key(capability: IndexCapability, gen_id: u64) -> Vec<u8> {
    let mut key = RETIRE_TOMBSTONE_PREFIX.to_vec();
    key.extend_from_slice(&gen_id.to_be_bytes());
    key.extend_from_slice(capability.name().as_bytes());
    key
}

fn decode_tombstone_key(key: &[u8]) -> Option<(u64, IndexCapability)> {
    let rest = key.strip_prefix(RETIRE_TOMBSTONE_PREFIX)?;
    if rest.len() < 9 {
        return None;
    }
    let gen_id = u64::from_be_bytes(rest[..8].try_into().ok()?);
    let name = core::str::from_utf8(&rest[8..]).ok()?;
    let capability = IndexCapability::ALL
        .into_iter()
        .find(|capability| capability.name() == name)?;
    Some((gen_id, capability))
}

/// Marker-first retirement of one sealed segment: the tombstone is durable
/// before any row clears, so recovery finishes an interrupted retirement on
/// open. Rows and the segment record never survive without the tombstone.
// REO-04, REO-05
pub fn retire_generation_rows<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    capability: IndexCapability,
    gen_id: u64,
) -> Result<(), crate::IndexError> {
    let mut tombstone_batch = store.new_batch();
    tombstone_batch.put(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        &retire_tombstone_key(capability, gen_id),
        &[],
    );
    store.write_durable(tombstone_batch)?;
    retire_fault(RetireFault::AfterTombstone)?;
    clear_retirement_rows(store, capability, gen_id)?;
    retire_fault(RetireFault::AfterClear)?;
    Ok(())
}
/// Families a retirement may clear for `capability` in a commit that retires
/// every capability in `retiring`: a shared family survives while a capability
/// outside `retiring` still publishes this generation.
// REO-05
fn retirement_target_families(
    snapshot: &dyn bitcoin_rs_storage::KvSnapshot,
    retiring: IndexCapabilities,
    capability: IndexCapability,
    gen_id: u64,
) -> Result<Vec<bitcoin_rs_storage::ColumnFamily>, crate::IndexError> {
    let mut families = retirement_families(capability).to_vec();
    let mut published: Vec<bitcoin_rs_storage::ColumnFamily> = Vec::new();
    for other in IndexCapability::ALL {
        if other == capability {
            continue;
        }
        let built = snapshot
            .get(
                bitcoin_rs_storage::ColumnFamily::IdxMeta,
                &sealed_gen_key(other, gen_id),
            )?
            .is_some();
        if !built {
            if other != IndexCapability::ScriptLive {
                families.extend_from_slice(retirement_families(other));
            }
        } else if !retiring.contains(other) {
            published.extend_from_slice(other.column_families());
        }
    }
    families.retain(|family| !published.contains(family));
    Ok(families)
}

/// Stages the retirement of one sealed generation for every capability in
/// `capabilities` in the caller's commit batch: the tombstones first, then the
/// row range deletes and marker clears. The batch commits atomically with the
/// watermark rewind, so a crash leaves the watermark and the rows in agreement
/// either way.
// REO-04, REO-05
pub fn stage_retirement<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    batch: &mut bitcoin_rs_storage::BufferedWriteBatch,
    capabilities: IndexCapabilities,
    gen_id: u64,
) -> Result<(), crate::IndexError> {
    for capability in capabilities.iter() {
        batch.put(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            &retire_tombstone_key(capability, gen_id),
            &[],
        );
    }
    retire_fault(RetireFault::AfterTombstone)?;
    let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
    let start = format::gen_prefix_start(gen_id);
    let end = format::gen_prefix_end(gen_id);
    for capability in capabilities.iter() {
        for family in
            retirement_target_families(snapshot.as_ref(), capabilities, capability, gen_id)?
        {
            batch.delete_range(family, &start, &end);
        }
        batch.delete(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            &sealed_gen_key(capability, gen_id),
        );
        batch.delete(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            &retire_tombstone_key(capability, gen_id),
        );
    }
    retire_fault(RetireFault::AfterClear)?;
    Ok(())
}

/// Retires one sealed segment end to end: rows, then the record, the
/// descriptor, and the tombstone in one batch.
pub fn retire_generation<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    capability: IndexCapability,
    gen_id: u64,
) -> Result<(), crate::IndexError> {
    retire_generation_rows(store, capability, gen_id)?;
    let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
    let mut state = tail::load(snapshot.as_ref())?;
    drop(snapshot);
    state.sealed.retain(|sealed| sealed.gen_id != gen_id);
    let mut batch = store.new_batch();
    batch.delete(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        &sealed_gen_key(capability, gen_id),
    );
    batch.delete(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        &retire_tombstone_key(capability, gen_id),
    );
    tail::put_generation_descriptors(&mut batch, [capability], state.bounds());
    store.write_durable(batch)?;
    retire_fault(RetireFault::AfterDescriptor)?;
    Ok(())
}

struct SealedRows {
    tx_dir: Vec<(Vec<u8>, Vec<u8>)>,
    spend_dir: Vec<(Vec<u8>, Vec<u8>)>,
    filters: Vec<(Vec<u8>, Vec<u8>)>,
    dict: Vec<(Vec<u8>, Vec<u8>)>,
    post: Vec<(Vec<u8>, Vec<u8>)>,
    stats: Vec<(Vec<u8>, Vec<u8>)>,
}

fn rekey_generation(key: &[u8], gen_id: u64) -> Option<Vec<u8>> {
    let mut out = key.to_vec();
    out.get_mut(..8)?.copy_from_slice(&gen_id.to_be_bytes());
    Some(out)
}

fn sealed_rows(plan: &tail::PrefixCut, gen_id: u64) -> SealedRows {
    let mut out = SealedRows {
        tx_dir: Vec::new(),
        spend_dir: Vec::new(),
        filters: Vec::new(),
        dict: Vec::new(),
        post: Vec::new(),
        stats: Vec::new(),
    };
    let mut posts: hashbrown::HashMap<u32, Vec<format::PostingItem>> = hashbrown::HashMap::new();
    for (family, key, value) in &plan.rows {
        let target = match family {
            tail::Family::TxDir => Some(&mut out.tx_dir),
            tail::Family::SpendDir => Some(&mut out.spend_dir),
            tail::Family::Filters => Some(&mut out.filters),
            tail::Family::ScriptPost => None,
            tail::Family::ScriptDict => None,
        };
        match (family, target) {
            (tail::Family::ScriptPost, _) => {
                if let (Some((_, old_id, _)), Some(items)) = (
                    format::decode_script_post_key(key),
                    format::decode_posting_items(value),
                ) {
                    posts.entry(old_id).or_default().extend(items);
                }
            }
            (_, Some(rows)) => {
                if let Some(new_key) = rekey_generation(key, gen_id) {
                    rows.push((new_key, value.clone()));
                }
            }
            _ => {}
        }
    }

    let mut prefix_scripts: Vec<([u8; 32], u32)> = plan
        .script_hashes
        .iter()
        .map(|(&old_id, &hash)| (hash, old_id))
        .collect();
    prefix_scripts.sort_unstable();
    let mut new_ids = hashbrown::HashMap::<u32, u32>::new();
    for (dense, (hash, old_id)) in prefix_scripts.into_iter().enumerate() {
        let Ok(new_id) = u32::try_from(dense) else {
            continue;
        };
        new_ids.insert(old_id, new_id);
        out.dict.push((
            format::encode_script_dict_key(gen_id, &hash).to_vec(),
            format::encode_script_dict_value(new_id).to_vec(),
        ));
        if let Some(stats) = plan.prefix_stats.get(&old_id) {
            out.stats.push((
                format::encode_script_stats_key(gen_id, new_id).to_vec(),
                format::encode_script_stats_value(stats).to_vec(),
            ));
        }
    }

    for (old_id, mut items) in posts {
        let Some(&new_id) = new_ids.get(&old_id) else {
            continue;
        };
        items.sort_unstable_by_key(|item| item.delta_ordinal);
        let mut last_ordinal = 0u32;
        let mut repacked = Vec::with_capacity(items.len());
        for item in items {
            let delta = item.delta_ordinal.saturating_sub(last_ordinal);
            last_ordinal = item.delta_ordinal;
            repacked.push(format::PostingItem {
                delta_ordinal: delta,
                flags: item.flags,
            });
        }
        out.post
            .extend(format::chunk_postings(gen_id, new_id, repacked));
    }
    out
}

// PRJ-03, PRJ-05, PRJ-09, REO-04
pub fn seal_tail_generation<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    gen_id: u64,
    cut: u32,
    capabilities: IndexCapabilities,
    scratch: &std::path::Path,
) -> Result<(), crate::IndexError> {
    let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
    let plan = tail::plan_prefix_cut(snapshot.as_ref(), cut)?;
    let mut capabilities = capabilities;
    for capability in IndexCapability::ALL {
        if capability == IndexCapability::ScriptLive
            || snapshot
                .get(
                    bitcoin_rs_storage::ColumnFamily::IdxMeta,
                    &meta_gen_key(capability),
                )?
                .is_none()
        {
            continue;
        }
        if plan.rows.iter().any(|(family, _, _)| match capability {
            IndexCapability::TxLookup => *family == tail::Family::TxDir,
            IndexCapability::ScriptHistory => matches!(
                family,
                tail::Family::TxDir
                    | tail::Family::ScriptDict
                    | tail::Family::ScriptPost
                    | tail::Family::SpendDir
            ),
            IndexCapability::CompactFilters => *family == tail::Family::Filters,
            IndexCapability::ScriptLive => false,
        }) {
            capabilities = capabilities.insert(capability);
        }
    }
    drop(snapshot);
    let coverage = Coverage::new(plan.first, plan.cut, plan.cut_hash);
    let mut rows = sealed_rows(&plan, gen_id);
    for list in [
        &mut rows.tx_dir,
        &mut rows.spend_dir,
        &mut rows.filters,
        &mut rows.dict,
        &mut rows.post,
        &mut rows.stats,
    ] {
        list.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    }

    let mut staging_batch = store.new_batch();
    staging_batch.put(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        SEAL_STAGING_KEY,
        &seal_marker_value(gen_id, &coverage, capabilities, plan.next_ordinal),
    );
    store.write_durable(staging_batch)?;
    seal_fault(SealFault::AfterStaging)?;

    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::TxDir,
        rows.tx_dir,
        scratch,
    )?;
    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::SpendDir,
        rows.spend_dir,
        scratch,
    )?;
    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::Filters,
        rows.filters,
        scratch,
    )?;
    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::ScriptDict,
        rows.dict,
        scratch,
    )?;
    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::ScriptPost,
        rows.post,
        scratch,
    )?;
    ingest_family_rows(
        store,
        bitcoin_rs_storage::ColumnFamily::ScriptStats,
        rows.stats,
        scratch,
    )?;
    seal_fault(SealFault::AfterIngest)?;

    let mut committed_batch = store.new_batch();
    committed_batch.put(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        SEAL_COMMITTED_KEY,
        &seal_marker_value(gen_id, &coverage, capabilities, plan.next_ordinal),
    );
    store.write_durable(committed_batch)?;
    seal_fault(SealFault::AfterCommitted)?;

    commit_cut(store, &plan, gen_id, coverage, capabilities)?;
    seal_fault(SealFault::AfterPublish)?;
    remove_seal_markers(store)?;
    Ok(())
}

fn commit_cut<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    plan: &tail::PrefixCut,
    gen_id: u64,
    coverage: Coverage,
    capabilities: IndexCapabilities,
) -> Result<(), crate::IndexError> {
    let sealed = SealedGen {
        gen_id,
        coverage,
        next_ordinal: plan.next_ordinal,
    };
    let mut batch = store.new_batch();
    tail::cut_generation_zero(&mut batch, plan);
    put_sealed_records(
        &mut batch,
        &sealed,
        capabilities,
        tail::TailBounds {
            newest: Some(sealed),
            first_height: plan.tail_first,
            at: plan.tail_at,
        },
    );
    store
        .write_durable(batch)
        .map_err(crate::IndexError::Storage)
}

fn put_sealed_records(
    batch: &mut bitcoin_rs_storage::BufferedWriteBatch,
    sealed: &SealedGen,
    capabilities: IndexCapabilities,
    bounds: tail::TailBounds,
) {
    let record = encode_sealed_gen(sealed);
    batch.put(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        SEAL_NEXT_GEN_KEY,
        &sealed.gen_id.saturating_add(1).to_le_bytes(),
    );
    let segment_caps: Vec<IndexCapability> = capabilities
        .iter()
        .filter(|capability| *capability != IndexCapability::ScriptLive)
        .collect();
    for &capability in &segment_caps {
        batch.put(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            &sealed_gen_key(capability, sealed.gen_id),
            &record,
        );
    }
    tail::put_generation_descriptors(batch, segment_caps, bounds);
}

pub fn publish_sealed<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    gen_id: u64,
    coverage: Coverage,
    next_ordinal: u32,
    capabilities: IndexCapabilities,
) -> Result<(), crate::IndexError> {
    let sealed = SealedGen {
        gen_id,
        coverage,
        next_ordinal,
    };
    let mut batch = store.new_batch();
    put_sealed_records(
        &mut batch,
        &sealed,
        capabilities,
        tail::TailBounds {
            newest: Some(sealed),
            first_height: None,
            at: Some((coverage.last_height, coverage.last_hash)),
        },
    );
    store
        .write_durable(batch)
        .map_err(crate::IndexError::Storage)
}

pub fn publish_bulk_generation<S: bitcoin_rs_storage::KvStore + ?Sized>(
    store: &S,
    gen_id: u64,
    coverage: Coverage,
    next_ordinal: u32,
    capabilities: IndexCapabilities,
) -> Result<(), crate::IndexError> {
    let descriptor = bulk_generation_descriptor(gen_id, coverage);
    let mut batch = store.new_batch();
    batch.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        crate::INDEX_FORMAT_VERSION_KEY,
        &crate::INDEX_FORMAT_VERSION_VALUE,
    );
    if next_ordinal == 0 {
        for capability in IndexCapability::ALL {
            batch.put(
                bitcoin_rs_storage::ColumnFamily::IdxMeta,
                &meta_gen_key(capability),
                &IndexGeneration::encode_meta_value(&descriptor),
            );
        }
    } else {
        let sealed = SealedGen {
            gen_id,
            coverage,
            next_ordinal,
        };
        put_sealed_records(
            &mut batch,
            &sealed,
            capabilities,
            tail::TailBounds {
                newest: Some(sealed),
                first_height: None,
                at: Some((coverage.last_height, coverage.last_hash)),
            },
        );
        crate::index::put_bulk_publish_marks(
            &mut batch,
            capabilities,
            crate::IndexWatermark {
                height: coverage.last_height,
                hash: coverage.last_hash,
            },
            coverage.first_height,
        );
        batch.put(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            &meta_gen_key(IndexCapability::ScriptLive),
            &IndexGeneration::encode_meta_value(&descriptor),
        );
    }
    store
        .write_durable(batch)
        .map_err(crate::IndexError::Storage)
}

fn bulk_generation_descriptor(gen_id: u64, coverage: Coverage) -> GenerationDescriptor {
    GenerationDescriptor {
        gen_id,
        coverage,
        tail: TailDescriptor {
            tail_lo: coverage.last_height.saturating_add(1),
            tail_hi: coverage.last_height,
            tail_hash: coverage.last_hash,
        },
    }
}

fn remove_seal_markers<S: bitcoin_rs_storage::KvStore>(store: &S) -> Result<(), crate::IndexError> {
    let mut batch = store.new_batch();
    batch.delete(bitcoin_rs_storage::ColumnFamily::IdxMeta, SEAL_STAGING_KEY);
    batch.delete(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        SEAL_COMMITTED_KEY,
    );
    store
        .write_durable(batch)
        .map_err(crate::IndexError::Storage)
}

/// Completes or rolls back an interrupted seal, then finishes any
/// tombstoned retirement. A seal staged without its committed marker rolls
/// back to the intact tail; once the committed marker exists the sealed
/// rows win and the tail clears, descriptors publish, and markers remove.
// PRJ-05, REO-04
pub fn recover_segments<S: bitcoin_rs_storage::KvStore>(
    store: &S,
) -> Result<(), crate::IndexError> {
    let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
    let staging = snapshot
        .get(bitcoin_rs_storage::ColumnFamily::IdxMeta, SEAL_STAGING_KEY)?
        .filter(|bytes| bytes.len() >= SEAL_MARKER_LEN);
    let committed = snapshot
        .get(
            bitcoin_rs_storage::ColumnFamily::IdxMeta,
            SEAL_COMMITTED_KEY,
        )?
        .filter(|bytes| bytes.len() >= SEAL_MARKER_LEN);
    drop(snapshot);

    let staged = staging.as_deref().map_or_else(
        || Err(crate::IndexError::InvalidSealMarker),
        |bytes| decode_seal_marker(bytes).ok_or(crate::IndexError::InvalidSealMarker),
    );
    if let Some(bytes) = committed.as_deref() {
        let (gen_id, coverage, capabilities, _next_ordinal) =
            decode_seal_marker(bytes).ok_or(crate::IndexError::InvalidSealMarker)?;
        let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
        let landed = snapshot
            .get(
                bitcoin_rs_storage::ColumnFamily::IdxMeta,
                &tail::log_key(coverage.first_height),
            )?
            .is_none();
        drop(snapshot);
        if !landed {
            let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
            let plan = tail::plan_prefix_cut(snapshot.as_ref(), coverage.last_height)?;
            drop(snapshot);
            commit_cut(store, &plan, gen_id, coverage, capabilities)?;
        }
        remove_seal_markers(store)?;
        if staged.is_err() {
            return Err(crate::IndexError::InvalidSealMarker);
        }
    } else if let Ok((gen_id, _coverage, _capabilities, _next)) = staged {
        rollback_seal(store, gen_id)?;
    }
    recover_retirements(store)
}

fn rollback_seal<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    gen_id: u64,
) -> Result<(), crate::IndexError> {
    let start = format::gen_prefix_start(gen_id);
    let end = format::gen_prefix_end(gen_id);
    for &cf in &SEALED_FAMILIES {
        store.delete_range(cf, &start, &end)?;
    }
    let mut batch = store.new_batch();
    batch.delete(bitcoin_rs_storage::ColumnFamily::IdxMeta, SEAL_STAGING_KEY);
    store
        .write_durable(batch)
        .map_err(crate::IndexError::Storage)
}

/// Finishes every tombstoned retirement: rows first, then the record, the
/// descriptor, and the tombstone in one batch.
fn recover_retirements<S: bitcoin_rs_storage::KvStore>(store: &S) -> Result<(), crate::IndexError> {
    let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
    let mut tombstones = Vec::new();
    for item in snapshot.iter_prefix(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        RETIRE_TOMBSTONE_PREFIX,
    )? {
        let (key, _value) = item?;
        if let Some((gen_id, capability)) = decode_tombstone_key(&key) {
            tombstones.push((key, gen_id, capability));
        }
    }
    drop(snapshot);

    for (key, gen_id, capability) in tombstones {
        finish_retirement(store, &key, gen_id, capability)?;
    }
    Ok(())
}

fn finish_retirement<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    tombstone: &[u8],
    gen_id: u64,
    capability: IndexCapability,
) -> Result<(), crate::IndexError> {
    clear_retirement_rows(store, capability, gen_id)?;
    let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
    let mut state = tail::load(snapshot.as_ref())?;
    drop(snapshot);
    state.sealed.retain(|sealed| sealed.gen_id != gen_id);
    let mut batch = store.new_batch();
    batch.delete(
        bitcoin_rs_storage::ColumnFamily::IdxMeta,
        &sealed_gen_key(capability, gen_id),
    );
    batch.delete(bitcoin_rs_storage::ColumnFamily::IdxMeta, tombstone);
    tail::put_generation_descriptors(&mut batch, [capability], state.bounds());
    store
        .write_durable(batch)
        .map_err(crate::IndexError::Storage)
}

fn clear_retirement_rows<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    capability: IndexCapability,
    gen_id: u64,
) -> Result<(), crate::IndexError> {
    let snapshot = store.snapshot().map_err(crate::IndexError::Storage)?;
    let families = retirement_target_families(
        snapshot.as_ref(),
        IndexCapabilities::from_iter([capability]),
        capability,
        gen_id,
    )?;
    drop(snapshot);
    let start = format::gen_prefix_start(gen_id);
    let end = format::gen_prefix_end(gen_id);
    for family in families {
        store.delete_range(family, &start, &end)?;
    }
    Ok(())
}

fn ingest_family_rows<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    cf: bitcoin_rs_storage::ColumnFamily,
    rows: Vec<(Vec<u8>, Vec<u8>)>,
    scratch: &std::path::Path,
) -> Result<(), crate::IndexError> {
    let mut row_iter = rows.into_iter();
    store
        .ingest_sorted(cf, &mut row_iter, scratch)
        .map_err(crate::IndexError::Storage)?;
    Ok(())
}

/// Key range covering every sealed segment record of `capability`.
#[must_use]
pub fn sealed_gen_range(capability: IndexCapability) -> (Vec<u8>, Vec<u8>) {
    let start = sealed_gen_prefix(capability);
    let mut end = start.clone();
    if let Some(last) = end.last_mut() {
        *last += 1;
    }
    (start, end)
}
