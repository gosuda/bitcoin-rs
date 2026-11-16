mod test_support_error;
mod adversarial_index {
    use std::collections::HashMap;
    use std::sync::Arc;

    use bitcoin_rs_consensus::primitives::{Hash256, encode};
    use bitcoin_rs_projection::types::{ScriptHash, ScriptHashRow, TxPosition};
    use bitcoin_rs_projection::{
        ConsumerCursorUpdate, IndexCapabilities, IndexError, IndexReader, IndexWatermark,
        IndexWriter, Indexer, PreparedBatch, PreparedBatchLimits, SpentCoin, SpentCoins,
    };
    use bitcoin_rs_storage::{ColumnFamily, KvStore, PrefixScanLimit};

    use crate::support::TestError;
    use crate::support::common::MemoryStore;

    const BLOCKS: u32 = 8;
    const SCAN_ALL: PrefixScanLimit = PrefixScanLimit {
        max_rows: 100_000,
        max_bytes: 64 << 20,
    };

    fn script_for(seed: u32) -> Vec<u8> {
        let mut script = Vec::with_capacity(22);
        script.push(0x00);
        script.push(0x14);
        script.extend_from_slice(&[0x22; 20]);
        script[2] = u8::try_from(seed % 251).unwrap_or(0);
        script[3] = u8::try_from((seed / 251) % 251).unwrap_or(0);
        script
    }

    #[derive(Default)]
    struct TestScripts {
        by_txid: HashMap<[u8; 32], Vec<u8>>,
    }

    impl SpentCoins for TestScripts {
        fn spent_coin(&self, txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
            self.by_txid.get(txid).map(|script| SpentCoin {
                script,
                value: 0,
                height: 0,
                coinbase: false,
            })
        }
    }

    struct TestChain {
        blocks: Vec<Vec<u8>>,
        hashes: Vec<Hash256>,
        coinbase_txids: Vec<[u8; 32]>,
        spend_txids: Vec<[u8; 32]>,
        scripts: TestScripts,
    }

    fn build_test_chain(blocks_count: u32) -> TestChain {
        let count = usize::try_from(blocks_count).unwrap_or(0);
        let mut blocks = Vec::with_capacity(count);
        let mut hashes = Vec::with_capacity(count);
        let mut coinbase_txids = Vec::with_capacity(count);
        let mut spend_txids = Vec::with_capacity(count);
        let mut scripts = TestScripts::default();
        let mut prev_hash = Hash256::from_le_bytes(&[0; 32]);

        for height in 0..blocks_count {
            let coinbase_script = script_for(height);
            let mut coinbase = Vec::new();
            coinbase.extend_from_slice(&1_u32.to_le_bytes());
            coinbase.push(0x01);
            coinbase.extend_from_slice(&[0_u8; 32]);
            coinbase.extend_from_slice(&u32::MAX.to_le_bytes());
            coinbase.push(0x02);
            coinbase.extend_from_slice(&[u8::try_from(height % 251).unwrap_or(0), 0xAA]);
            coinbase.extend_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
            coinbase.push(0x01);
            coinbase.extend_from_slice(&500_000_000_u64.to_le_bytes());
            coinbase.push(u8::try_from(coinbase_script.len()).unwrap_or(0));
            coinbase.extend_from_slice(&coinbase_script);
            coinbase.extend_from_slice(&0_u32.to_le_bytes());
            let coinbase_txid = encode::double_sha256(&coinbase);
            coinbase_txids.push(coinbase_txid.to_le_bytes());
            scripts
                .by_txid
                .insert(coinbase_txid.to_le_bytes(), coinbase_script.clone());

            let mut spend = Vec::new();
            if height > 0 {
                let spend_script = script_for(2_000 + height);
                spend.extend_from_slice(&1_u32.to_le_bytes());
                spend.push(0x01);
                spend.extend_from_slice(
                    &coinbase_txids[usize::try_from(height.saturating_sub(1)).unwrap_or(0)],
                );
                spend.extend_from_slice(&0_u32.to_le_bytes());
                spend.push(0x00);
                spend.extend_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
                spend.push(0x01);
                spend.extend_from_slice(&1_000_u64.to_le_bytes());
                spend.push(u8::try_from(spend_script.len()).unwrap_or(0));
                spend.extend_from_slice(&spend_script);
                spend.extend_from_slice(&0_u32.to_le_bytes());
                spend_txids.push(encode::double_sha256(&spend).to_le_bytes());
            }

            let mut body = Vec::new();
            body.extend_from_slice(&1_i32.to_le_bytes());
            body.extend_from_slice(&prev_hash.to_le_bytes());
            let merkle_root = if height == 0 {
                coinbase_txid
            } else {
                encode::double_sha256(
                    &[
                        coinbase_txid.to_le_bytes().as_slice(),
                        spend_txids.last().unwrap_or(&[0; 32]),
                    ]
                    .concat(),
                )
            };
            body.extend_from_slice(&merkle_root.to_le_bytes());
            body.extend_from_slice(&1_234_567_u32.to_le_bytes());
            body.extend_from_slice(&0x1d00_ffff_u32.to_le_bytes());
            body.extend_from_slice(&height.to_le_bytes());
            let tx_count = if height == 0 { 1 } else { 2 };
            body.push(tx_count);
            body.extend_from_slice(&coinbase);
            if height > 0 {
                body.extend_from_slice(&spend);
            }
            let hash = encode::double_sha256(&body[..80]);
            prev_hash = hash;
            hashes.push(hash);
            blocks.push(body);
        }

        TestChain {
            blocks,
            hashes,
            coinbase_txids,
            spend_txids,
            scripts,
        }
    }

    fn commit_test_chain<S: KvStore + 'static>(
        writer: &mut IndexWriter<S>,
        chain: &TestChain,
    ) -> Result<Vec<IndexWatermark>, IndexError> {
        let mut watermarks = Vec::with_capacity(chain.blocks.len());
        for (height, body) in chain.blocks.iter().enumerate() {
            let hash = chain.hashes[height];
            let prepared = writer.prepare_block_with_spent_scripts(
                IndexCapabilities::HISTORICAL,
                u32::try_from(height).unwrap_or(0),
                hash.to_le_bytes(),
                body,
                &chain.scripts,
            )?;
            let mut batch = PreparedBatch::new(PreparedBatchLimits {
                max_rows: usize::MAX,
                max_bytes: usize::MAX,
            });
            assert!(batch.try_push(prepared).is_ok());
            watermarks.push(writer.commit_forward(batch)?);
        }
        Ok(watermarks)
    }

    #[test]
    fn wrong_format_version_refuses_open() -> Result<(), TestError> {
        for wrong_version in [0_u32, 1, 5, 6, 7, u32::MAX] {
            let store = Arc::new(MemoryStore::default());
            store.put(
                ColumnFamily::UtxoMeta,
                &[0x00, b'V'],
                &wrong_version.to_le_bytes(),
            )?;
            let result = IndexWriter::open(Arc::clone(&store), 1);
            let Err(err) = result else {
                return Err(TestError::Message(format!(
                    "version {wrong_version} must refuse open"
                )));
            };
            assert!(
                matches!(
                    err,
                    IndexError::UnsupportedTxIndexFormatVersion { version } if version == wrong_version
                ),
                "version {wrong_version} must refuse open with UnsupportedTxIndexFormatVersion"
            );
            let err_msg = err.to_string();
            assert!(
                err_msg.contains("bitcoin-rs-storage-convert rebuild-index"),
                "version {wrong_version} error must contain rebuild-index guidance: {err_msg}"
            );
        }
        Ok(())
    }

    #[test]
    fn legacy_cursorless_index_without_version_marker_refuses_open() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        store.put(ColumnFamily::Funding, &[0xAA; 12], &[0xBB; 71])?;
        let result = IndexWriter::open(Arc::clone(&store), 1);
        let Err(err) = result else {
            return Err(TestError::Message(
                "unversioned store must refuse open".into(),
            ));
        };
        assert!(
            matches!(err, IndexError::LegacyCursorlessIndex),
            "unversioned store with existing rows must refuse open with LegacyCursorlessIndex"
        );
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("bitcoin-rs-storage-convert rebuild-index"),
            "legacy unversioned store error must contain rebuild-index guidance: {err_msg}"
        );
        Ok(())
    }

    #[test]
    fn marker_in_idx_meta_is_not_accepted_as_format_marker() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        store.put(ColumnFamily::IdxMeta, &[0x00, b'V'], &7_u32.to_le_bytes())?;
        let result = IndexWriter::open(Arc::clone(&store), 1);
        let Err(err) = result else {
            return Err(TestError::Message(
                "marker in IdxMeta must refuse open".into(),
            ));
        };
        assert!(
            matches!(err, IndexError::LegacyCursorlessIndex),
            "marker in IdxMeta must not be accepted; format marker must reside in UtxoMeta"
        );
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("bitcoin-rs-storage-convert rebuild-index"),
            "error must contain rebuild-index guidance: {err_msg}"
        );
        Ok(())
    }

    #[test]
    fn row_ordering_invariants_hold() {
        let script = ScriptHash::from_script_bytes(&[1, 2, 3]);
        let mut previous_be = 0_u32;
        for height in 1..1_000_u32 {
            let row = ScriptHashRow::row(script, height);
            assert_eq!(row.height(), height);
            let num = u32::from_be_bytes(row.height);
            assert!(
                num > previous_be,
                "big endian height must strictly increase as height increases"
            );
            previous_be = num;
        }

        let p1 = TxPosition::new(100, 50);
        let p2 = TxPosition::new(100, 60);
        let p3 = TxPosition::new(200, 10);
        assert!(p1 < p2, "positions at same offset order by length");
        assert!(
            p2 < p3,
            "positions at earlier offset order before later offset"
        );
    }

    #[test]
    fn query_pagination_limits_and_boundaries() -> Result<(), TestError> {
        let chain = build_test_chain(BLOCKS);
        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        commit_test_chain(&mut writer, &chain)?;
        assert_eq!(
            chain.coinbase_txids.len(),
            usize::try_from(BLOCKS).unwrap_or(0)
        );
        assert_eq!(
            chain.spend_txids.len(),
            usize::try_from(BLOCKS - 1).unwrap_or(0)
        );
        let indexer = Indexer::new(Arc::clone(&store));
        let snapshot = indexer.snapshot()?;
        let script = ScriptHash::from_script_bytes(&script_for(0));

        let scan_zero = snapshot.funding_rows_from(
            script,
            u32::MAX,
            PrefixScanLimit {
                max_rows: 0,
                max_bytes: 64 << 20,
            },
        )?;
        assert_eq!(scan_zero.rows.len(), 0, "limit 0 returns zero rows");

        let scan_one = snapshot.funding_rows_from(
            script,
            u32::MAX,
            PrefixScanLimit {
                max_rows: 1,
                max_bytes: 64 << 20,
            },
        )?;
        assert_eq!(scan_one.rows.len(), 1, "limit 1 returns exactly one row");

        let scan_all = snapshot.funding_rows_from(script, u32::MAX, SCAN_ALL)?;
        assert!(
            scan_all.rows.len() >= 2,
            "script has funding and spending occurrences"
        );

        let foreign_script = ScriptHash::from_script_bytes(&script_for(999));
        let scan_foreign = snapshot.funding_rows_from(foreign_script, u32::MAX, SCAN_ALL)?;
        assert_eq!(
            scan_foreign.rows.len(),
            0,
            "foreign script returns empty scan"
        );

        Ok(())
    }

    #[test]
    fn rollback_and_catchup_crash_window_step_failures() -> Result<(), TestError> {
        let chain = build_test_chain(BLOCKS);
        let store = Arc::new(MemoryStore::default());

        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let first = writer.prepare_block_with_spent_scripts(
            IndexCapabilities::HISTORICAL,
            0,
            chain.hashes[0].to_le_bytes(),
            &chain.blocks[0],
            &chain.scripts,
        )?;
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        assert!(batch.try_push(first).is_ok());
        writer.commit_forward(batch)?;
        assert_eq!(writer.watermark()?.map(|w| w.height), Some(0));

        let corrupt_body = vec![0xFF; 20];
        let bad_prepare = writer.prepare_block_with_spent_scripts(
            IndexCapabilities::HISTORICAL,
            1,
            chain.hashes[1].to_le_bytes(),
            &corrupt_body,
            &chain.scripts,
        );
        assert!(
            matches!(bad_prepare, Err(IndexError::BlockParse(_))),
            "corrupt block body fails prepare"
        );
        assert_eq!(writer.watermark()?.map(|w| w.height), Some(0));

        drop(writer);
        let mut writer = IndexWriter::open(Arc::clone(&store), 2)?;
        assert_eq!(writer.watermark()?.map(|w| w.height), Some(0));

        let second = writer.prepare_block_with_spent_scripts(
            IndexCapabilities::HISTORICAL,
            1,
            chain.hashes[1].to_le_bytes(),
            &chain.blocks[1],
            &chain.scripts,
        )?;
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        assert!(batch.try_push(second).is_ok());
        store.arm_fenced_write_failure();
        assert!(writer.commit_forward(batch).is_err());
        assert_eq!(writer.watermark()?.map(|w| w.height), Some(0));

        drop(writer);
        let mut writer = IndexWriter::open(Arc::clone(&store), 3)?;
        assert_eq!(writer.watermark()?.map(|w| w.height), Some(0));

        let second = writer.prepare_block_with_spent_scripts(
            IndexCapabilities::HISTORICAL,
            1,
            chain.hashes[1].to_le_bytes(),
            &chain.blocks[1],
            &chain.scripts,
        )?;
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        assert!(batch.try_push(second).is_ok());
        writer.commit_forward(batch)?;
        assert_eq!(writer.watermark()?.map(|w| w.height), Some(1));

        let (fence, _) = writer.fenced_watermarks()?;
        let prev_watermark = IndexWatermark {
            height: 0,
            hash: chain.hashes[0].to_le_bytes(),
        };
        store.arm_fenced_write_failure();
        let rollback_result = writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            IndexCapabilities::HISTORICAL,
            Some(prev_watermark),
            &chain.blocks[1],
            ConsumerCursorUpdate::Keep,
            &chain.scripts,
        );
        assert!(rollback_result.is_err(), "injected rollback write failure");
        assert_eq!(writer.watermark()?.map(|w| w.height), Some(1));

        drop(writer);
        let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
        assert_eq!(writer.watermark()?.map(|w| w.height), Some(1));

        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            IndexCapabilities::HISTORICAL,
            Some(prev_watermark),
            &chain.blocks[1],
            ConsumerCursorUpdate::Keep,
            &chain.scripts,
        )?;
        assert_eq!(writer.watermark()?.map(|w| w.height), Some(0));

        drop(writer);
        let writer = IndexWriter::open(Arc::clone(&store), 5)?;
        assert_eq!(writer.watermark()?.map(|w| w.height), Some(0));

        Ok(())
    }
}
mod bip30_rollback {
    //! BIP30 rollback: a block whose coinbase repeats an earlier unspent coinbase
    //! overwrites that coin's ScriptLive row, because both coins share one key.
    //! Disconnecting the later block restores the earlier coin in the chainstate,
    //! so rolling the later block back must leave exactly that coin's row, at the
    //! earlier height.

    use std::sync::Arc;

    use bitcoin_rs_consensus::primitives::encode::double_sha256;
    use bitcoin_rs_projection::types::ScriptLiveCoin;
    use bitcoin_rs_projection::{
        ConsumerCursorUpdate, IndexCapabilities, IndexWatermark, IndexWriter, PreparedBatch,
        PreparedBatchLimits, SpentCoin, SpentCoins,
    };
    use bitcoin_rs_storage::{ColumnFamily, KvStore};

    use crate::support::TestError;
    use crate::support::common::MemoryStore;

    const COINBASE_VALUE: u64 = 50 * 100_000_000;
    const OP_TRUE: [u8; 1] = [0x51];

    struct NoCoins;

    impl SpentCoins for NoCoins {
        fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
            None
        }
    }

    /// The chainstate view while the later block is disconnected: the coin that
    /// the duplicate overwrote comes back at its original height and value.
    struct RestoredCoin;

    impl SpentCoins for RestoredCoin {
        fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
            Some(SpentCoin {
                script: &OP_TRUE,
                value: COINBASE_VALUE,
                height: 1,
                coinbase: true,
            })
        }
    }

    fn coinbase(script_sig: Vec<u8>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&1_i32.to_le_bytes());
        out.push(1);
        out.extend_from_slice(&[0; 32]);
        out.extend_from_slice(&u32::MAX.to_le_bytes());
        out.push(u8::try_from(script_sig.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(&script_sig);
        out.extend_from_slice(&u32::MAX.to_le_bytes());
        out.push(1);
        out.extend_from_slice(&COINBASE_VALUE.to_le_bytes());
        out.push(u8::try_from(OP_TRUE.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(&OP_TRUE);
        out.extend_from_slice(&0_u32.to_le_bytes());
        out
    }

    struct Block {
        body: Vec<u8>,
        hash: [u8; 32],
    }

    fn block(prev: [u8; 32], height: u32, tx: &[u8]) -> Block {
        let mut header = [0_u8; 80];
        header[..4].copy_from_slice(&1_i32.to_le_bytes());
        header[4..36].copy_from_slice(&prev);
        header[68..72].copy_from_slice(&height.to_le_bytes());
        header[72..76].copy_from_slice(&0x207f_ffff_u32.to_le_bytes());
        header[76..80].copy_from_slice(&height.to_le_bytes());
        let hash = double_sha256(&header).to_le_bytes();
        let mut body = header.to_vec();
        body.push(1);
        body.extend_from_slice(tx);
        Block { body, hash }
    }

    fn live_rows_for_outpoint(
        store: &MemoryStore,
        txid: &[u8; 32],
    ) -> Result<Vec<Vec<u8>>, TestError> {
        let mut suffix = txid.to_vec();
        suffix.extend_from_slice(&[0, 0, 0]);
        let mut values = Vec::new();
        for item in store.iter_prefix(ColumnFamily::ScriptLive, &[])? {
            let (key, value) = item?;
            if key.ends_with(&suffix) {
                values.push(value);
            }
        }
        Ok(values)
    }

    // IDX-06
    #[test]
    fn rolling_back_a_bip30_duplicate_restores_the_earlier_coin_row() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let caps = IndexCapabilities::ALL;

        let genesis_tx = coinbase(vec![0x00, 0x00]);
        let duplicated_tx = coinbase(vec![0x01, 0x01]);
        let duplicated_txid = double_sha256(&duplicated_tx).to_le_bytes();

        let b0 = block([0; 32], 0, &genesis_tx);
        let b1 = block(b0.hash, 1, &duplicated_tx);
        let b2 = block(b1.hash, 2, &duplicated_tx);

        for (height, hash, body) in [
            (0, b0.hash, &b0.body),
            (1, b1.hash, &b1.body),
            (2, b2.hash, &b2.body),
        ] {
            let prepared =
                writer.prepare_block_with_spent_scripts(caps, height, hash, body, &NoCoins)?;
            let mut batch = PreparedBatch::new(PreparedBatchLimits {
                max_rows: usize::MAX,
                max_bytes: usize::MAX,
            });
            assert!(batch.try_push(prepared).is_ok());
            writer.commit_forward(batch)?;
        }
        assert_eq!(
            live_rows_for_outpoint(&store, &duplicated_txid)?.len(),
            1,
            "the duplicate overwrites the earlier coin's row while both blocks are connected"
        );

        let fence = writer.fenced_watermarks()?.0;
        writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            caps,
            Some(IndexWatermark {
                height: 1,
                hash: b1.hash,
            }),
            &b2.body,
            ConsumerCursorUpdate::Keep,
            &RestoredCoin,
        )?;

        let rows = live_rows_for_outpoint(&store, &duplicated_txid)?;
        assert_eq!(
            rows.len(),
            1,
            "rolling back the later duplicate leaves the earlier coin's row, as the chainstate does"
        );
        let restored = ScriptLiveCoin::decode_value(&rows[0])?;
        assert_eq!(
            restored.height, 1,
            "the restored row is the earlier coin, created at height 1"
        );
        Ok(())
    }
}
mod compact_filter_artifact {
    #![expect(
        clippy::expect_used,
        reason = "test: fixture setup failures abort the test with context"
    )]

    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::{Hash as _, sha256, sha256d};
    use bitcoin::hex::FromHex as _;
    use bitcoin_rs_consensus::primitives::Network;
    use bitcoin_rs_projection::portable::{
        CompactFilterArtifact, IndexBundleError, ManifestArtifactTarget, SpillBudget,
        attach_compact_filter_artifact, write_compact_filter_artifact,
    };
    use bitcoin_rs_projection::{
        IndexCapabilities, IndexCapability, IndexError, IndexReader, IndexWatermark, IndexWriter,
        PreparedBatch, PreparedBatchLimits, SpentCoin, SpentCoins, index_format_version,
    };
    use bitcoin_rs_storage::{ColumnFamily, KvStore};
    use parking_lot::RwLock;

    use crate::support::common::MemoryStore;

    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/storage/fixtures/core-v2/blocks200.json"
    );
    const HEADER_LEN: usize = 73;
    const RECORD_FIXED_LEN: usize = 104;
    const FILTER_HASH_AT: usize = 36;
    const LENGTH_AT: usize = 100;
    const UTXO_FILTER_PREFIX: [u8; 2] = [1, b'F'];

    struct Fixture {
        raw: Vec<Vec<u8>>,
        blocks: Vec<bitcoin::Block>,
        hashes: Vec<[u8; 32]>,
    }

    type OutputMap = HashMap<([u8; 32], u32), (Vec<u8>, u64, u32, bool)>;

    struct FixtureOutputs(OutputMap);

    impl SpentCoins for FixtureOutputs {
        fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<SpentCoin<'_>> {
            self.0
                .get(&(*txid, vout))
                .map(|(script, value, height, coinbase)| SpentCoin {
                    script,
                    value: *value,
                    height: *height,
                    coinbase: *coinbase,
                })
        }
    }

    fn load_fixture() -> Fixture {
        let text = fs::read_to_string(FIXTURE).expect("core-v2 block fixture");
        let hexes: Vec<String> =
            sonic_rs::from_str(&text).expect("block fixture is a JSON array of hex strings");
        let raw: Vec<Vec<u8>> = hexes
            .iter()
            .map(|hex| Vec::<u8>::from_hex(hex).expect("fixture block is hex"))
            .collect();
        let blocks: Vec<bitcoin::Block> = raw
            .iter()
            .map(|bytes| deserialize(bytes).expect("fixture block decodes"))
            .collect();
        for pair in blocks.windows(2) {
            assert_eq!(
                pair[1].header.prev_blockhash,
                pair[0].block_hash(),
                "fixture blocks form one chain in list order"
            );
        }
        let hashes = blocks
            .iter()
            .map(|block| block.block_hash().to_byte_array())
            .collect();
        Fixture {
            raw,
            blocks,
            hashes,
        }
    }

    fn fixture_outputs(fixture: &Fixture) -> FixtureOutputs {
        let mut outputs = HashMap::new();
        for (index, block) in fixture.blocks.iter().enumerate() {
            let height = u32::try_from(index).expect("fixture height fits in u32");
            for tx in &block.txdata {
                let txid = tx.compute_txid().to_byte_array();
                for (vout, output) in tx.output.iter().enumerate() {
                    let vout = u32::try_from(vout).expect("fixture vout fits in u32");
                    outputs.insert(
                        (txid, vout),
                        (
                            output.script_pubkey.as_bytes().to_vec(),
                            output.value.to_sat(),
                            height,
                            tx.is_coinbase(),
                        ),
                    );
                }
            }
        }
        FixtureOutputs(outputs)
    }

    fn build_source(fixture: &Fixture) -> IndexWriter<MemoryStore> {
        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(store, 1).expect("source writer");
        let spent = fixture_outputs(fixture);
        for (index, body) in fixture.raw.iter().enumerate() {
            let height = u32::try_from(index).expect("fixture height fits in u32");
            let prepared = writer
                .prepare_block_with_spent_scripts(
                    IndexCapabilities::COMPACT_FILTERS,
                    height,
                    fixture.hashes[index],
                    body,
                    &spent,
                )
                .expect("fixture block prepares");
            let mut batch = PreparedBatch::new(PreparedBatchLimits {
                max_rows: usize::MAX,
                max_bytes: usize::MAX,
            });
            assert!(batch.try_push(prepared).is_ok(), "one block per batch");
            writer.commit_forward(batch).expect("fixture block commits");
        }
        writer
    }

    fn produce(
        source: &IndexWriter<MemoryStore>,
        fixture: &Fixture,
        network: Network,
        dir: &Path,
        name: &str,
    ) -> (PathBuf, CompactFilterArtifact) {
        let path = dir.join(name);
        let artifact = write_compact_filter_artifact(source, network, &fixture.hashes, &path)
            .expect("producer writes the artifact");
        (path, artifact)
    }

    fn base_at_tip(fixture: &Fixture) -> IndexWatermark {
        let last = fixture.blocks.len() - 1;
        IndexWatermark {
            height: u32::try_from(last).expect("fixture height fits in u32"),
            hash: fixture.hashes[last],
        }
    }

    fn target(
        artifact: &Path,
        base: IndexWatermark,
        sha256: [u8; 32],
        size_bytes: u64,
    ) -> ManifestArtifactTarget {
        ManifestArtifactTarget {
            artifact_path: artifact.to_path_buf(),
            base_height: base.height,
            base_hash: base.hash,
            floor: 0,
            network: Network::Regtest,
            index_format: index_format_version(),
            sha256,
            size_bytes,
            chain_tx_count: 0,
        }
    }

    fn empty_receiver() -> (Arc<MemoryStore>, RwLock<IndexWriter<MemoryStore>>) {
        let store = Arc::new(MemoryStore::default());
        let writer = IndexWriter::open(Arc::clone(&store), 1).expect("receiver writer");
        (store, RwLock::new(writer))
    }

    fn rows_with_prefix(store: &MemoryStore, cf: ColumnFamily, prefix: &[u8]) -> usize {
        store
            .iter_prefix(cf, prefix)
            .expect("family scan")
            .collect::<Result<Vec<_>, _>>()
            .expect("family rows")
            .len()
    }

    fn assert_untouched(store: &MemoryStore, receiver: &RwLock<IndexWriter<MemoryStore>>) {
        assert_eq!(
            receiver
                .read()
                .watermarks()
                .expect("watermarks")
                .compact_filters,
            None,
            "a refused artifact publishes no watermark"
        );
        assert_eq!(
            rows_with_prefix(store, ColumnFamily::UtxoMeta, &UTXO_FILTER_PREFIX),
            0,
            "a refused artifact writes no filter rows"
        );
        assert_eq!(
            rows_with_prefix(store, ColumnFamily::Filters, &[]),
            0,
            "a refused artifact writes no height-keyed filter rows"
        );
    }

    fn record_offset(bytes: &[u8], wanted: usize) -> usize {
        let mut at = HEADER_LEN;
        for _ in 0..wanted {
            let mut length = [0_u8; 4];
            length.copy_from_slice(&bytes[at + LENGTH_AT..at + LENGTH_AT + 4]);
            at += RECORD_FIXED_LEN + usize::try_from(u32::from_le_bytes(length)).expect("fits");
        }
        at
    }

    #[test]
    fn compact_filter_artifact_attaches_and_serves_the_live_rows_at_its_base() {
        let fixture = load_fixture();
        let source = build_source(&fixture);
        let root = tempfile::tempdir().expect("tempdir");
        let (path, artifact) =
            produce(&source, &fixture, Network::Regtest, root.path(), "good.dat");
        let base = base_at_tip(&fixture);
        assert_eq!(artifact.base, base, "the artifact is cut at the live base");
        let records = u64::try_from(fixture.hashes.len()).expect("fits");
        assert_eq!(artifact.records, records);

        let (receiver_store, receiver) = empty_receiver();
        let attached = attach_compact_filter_artifact(
            &receiver,
            &target(&path, base, artifact.sha256, artifact.bytes),
            root.path(),
            &SpillBudget::new(u64::MAX),
        )
        .expect("a verified artifact attaches");
        assert_eq!(attached, records);

        let receiver_guard = receiver.read();
        let served = receiver_guard.snapshot().expect("receiver snapshot");
        let live = source.snapshot().expect("source snapshot");
        assert_eq!(
            served
                .capability_watermark(IndexCapability::CompactFilters)
                .expect("watermark read"),
            Some(base),
            "coverage is published at the base"
        );
        assert_eq!(
            rows_with_prefix(&receiver_store, ColumnFamily::Filters, &[]),
            fixture.hashes.len(),
            "one height-keyed row per block"
        );

        let mut previous = [0_u8; 32];
        for (height, hash) in fixture.hashes.iter().enumerate() {
            let height = u32::try_from(height).expect("fixture height fits u32");
            let attached_filter = served
                .compact_filter(height, hash)
                .expect("filter read")
                .expect("attached row");
            let live_filter = live
                .compact_filter(height, hash)
                .expect("live filter read")
                .expect("live row");
            assert_eq!(
                attached_filter, live_filter,
                "height {height} matches the live writer"
            );
            let filter_hash = sha256d::Hash::hash(&attached_filter.filter).to_byte_array();
            assert_eq!(
                attached_filter.hash, filter_hash,
                "height {height} filter hash is dSHA256 of the filter bytes"
            );
            let mut chained = [0_u8; 64];
            chained[..32].copy_from_slice(&filter_hash);
            chained[32..].copy_from_slice(&previous);
            let header = sha256d::Hash::hash(&chained).to_byte_array();
            assert_eq!(
                attached_filter.header, header,
                "height {height} header chains from the previous header"
            );
            previous = header;
        }
    }
    // SNP-05
    #[test]
    fn small_budget_compact_filter_restore_matches_live_rows() {
        let fixture = load_fixture();
        let source = build_source(&fixture);
        let root = tempfile::tempdir().expect("tempdir");
        let (path, artifact) = produce(
            &source,
            &fixture,
            Network::Regtest,
            root.path(),
            "bounded.dat",
        );
        let size = fs::metadata(&path).expect("artifact metadata").len();
        let base = base_at_tip(&fixture);
        let decoded = size.saturating_sub(u64::try_from(HEADER_LEN).expect("header fits u64"));
        let budget = SpillBudget::new(4096);
        assert!(
            decoded > budget.peak_bytes().max(4096),
            "the artifact must exceed the budget to prove streaming: {decoded} <= 4096"
        );

        let (receiver_store, receiver) = empty_receiver();
        let attached = attach_compact_filter_artifact(
            &receiver,
            &target(&path, base, artifact.sha256, artifact.bytes),
            root.path(),
            &budget,
        )
        .expect("a bounded re-encode attaches");
        assert_eq!(attached, artifact.records);
        assert!(
            budget.peak_bytes() > 0,
            "the bounded re-encode charges its rows to the budget"
        );
        assert!(
            budget.peak_bytes() <= 4096,
            "the re-encode buffered {} bytes above the 4096-byte budget",
            budget.peak_bytes()
        );

        let receiver_guard = receiver.read();
        let served = receiver_guard.snapshot().expect("receiver snapshot");
        let live = source.snapshot().expect("source snapshot");
        for (height, hash) in fixture.hashes.iter().enumerate() {
            let height = u32::try_from(height).expect("fixture height fits u32");
            let attached_filter = served
                .compact_filter(height, hash)
                .expect("filter read")
                .expect("attached row");
            let live_filter = live
                .compact_filter(height, hash)
                .expect("live filter read")
                .expect("live row");
            assert_eq!(
                attached_filter, live_filter,
                "height {height} matches the live writer"
            );
        }
        assert_eq!(
            rows_with_prefix(&receiver_store, ColumnFamily::Filters, &[]),
            fixture.hashes.len(),
            "one height-keyed row per block"
        );
    }

    #[test]
    fn compact_filter_artifact_forged_digest_is_refused_without_rows() {
        let fixture = load_fixture();
        let source = build_source(&fixture);
        let root = tempfile::tempdir().expect("tempdir");
        let (path, artifact) = produce(
            &source,
            &fixture,
            Network::Regtest,
            root.path(),
            "forged.dat",
        );
        let mut forged = artifact.sha256;
        forged[0] ^= 0x01;

        let (receiver_store, receiver) = empty_receiver();
        let error = attach_compact_filter_artifact(
            &receiver,
            &target(&path, base_at_tip(&fixture), forged, artifact.bytes),
            root.path(),
            &SpillBudget::new(u64::MAX),
        )
        .expect_err("a forged digest is refused");
        assert!(
            matches!(error, IndexBundleError::ArtifactHash { .. }),
            "got {error:?}"
        );
        assert_untouched(&receiver_store, &receiver);
    }

    #[test]
    fn compact_filter_artifact_broken_header_chain_is_refused_without_rows() {
        let fixture = load_fixture();
        let source = build_source(&fixture);
        let root = tempfile::tempdir().expect("tempdir");
        let (path, _artifact) = produce(
            &source,
            &fixture,
            Network::Regtest,
            root.path(),
            "chain.dat",
        );
        let mut bytes = fs::read(&path).expect("artifact bytes");
        let broken: usize = 37;
        let at = record_offset(&bytes, broken);
        let mut length = [0_u8; 4];
        length.copy_from_slice(&bytes[at + LENGTH_AT..at + LENGTH_AT + 4]);
        let length = usize::try_from(u32::from_le_bytes(length)).expect("fits");
        assert!(length > 1, "the record carries a filter");
        let filter_start = at + RECORD_FIXED_LEN;
        bytes[filter_start + 1] ^= 0x01;
        let new_filter_hash =
            sha256d::Hash::hash(&bytes[filter_start..filter_start + length]).to_byte_array();
        bytes[at + FILTER_HASH_AT..at + FILTER_HASH_AT + 32].copy_from_slice(&new_filter_hash);
        let tampered = root.path().join("chain-tampered.dat");
        fs::write(&tampered, &bytes).expect("tampered artifact");
        let digest = sha256::Hash::hash(&bytes).to_byte_array();

        let (receiver_store, receiver) = empty_receiver();
        let error = attach_compact_filter_artifact(
            &receiver,
            &target(
                &tampered,
                base_at_tip(&fixture),
                digest,
                u64::try_from(bytes.len()).expect("fits"),
            ),
            root.path(),
            &SpillBudget::new(u64::MAX),
        )
        .expect_err("a broken filter header chain is refused");
        assert!(
            matches!(
                error,
                IndexBundleError::ArtifactFraming { record, .. }
                    if record == u64::try_from(broken).expect("fits")
            ),
            "got {error:?}"
        );
        assert_untouched(&receiver_store, &receiver);
    }

    #[test]
    fn compact_filter_artifact_foreign_base_hash_is_refused_without_rows() {
        let fixture = load_fixture();
        let source = build_source(&fixture);
        let root = tempfile::tempdir().expect("tempdir");
        let (path, artifact) =
            produce(&source, &fixture, Network::Regtest, root.path(), "base.dat");
        let mut foreign = base_at_tip(&fixture);
        foreign.hash[0] ^= 0x01;

        let (receiver_store, receiver) = empty_receiver();
        let error = attach_compact_filter_artifact(
            &receiver,
            &target(&path, foreign, artifact.sha256, artifact.bytes),
            root.path(),
            &SpillBudget::new(u64::MAX),
        )
        .expect_err("a foreign base hash is refused");
        assert!(
            matches!(error, IndexBundleError::ArtifactHeader { .. }),
            "got {error:?}"
        );
        assert_untouched(&receiver_store, &receiver);
    }

    #[test]
    fn compact_filter_artifact_truncated_payload_is_refused_without_rows() {
        let fixture = load_fixture();
        let source = build_source(&fixture);
        let root = tempfile::tempdir().expect("tempdir");
        let (path, _artifact) =
            produce(&source, &fixture, Network::Regtest, root.path(), "full.dat");
        let bytes = fs::read(&path).expect("artifact bytes");
        let short = &bytes[..bytes.len() - 5];
        let truncated = root.path().join("short.dat");
        fs::write(&truncated, short).expect("truncated artifact");
        let digest = sha256::Hash::hash(short).to_byte_array();

        let (receiver_store, receiver) = empty_receiver();
        let error = attach_compact_filter_artifact(
            &receiver,
            &target(
                &truncated,
                base_at_tip(&fixture),
                digest,
                u64::try_from(short.len()).expect("fits"),
            ),
            root.path(),
            &SpillBudget::new(u64::MAX),
        )
        .expect_err("a truncated payload is refused");
        assert!(
            matches!(error, IndexBundleError::ArtifactHeader { .. }),
            "got {error:?}"
        );
        assert_untouched(&receiver_store, &receiver);
    }

    #[test]
    fn compact_filter_artifact_second_attach_over_populated_family_is_refused() {
        let fixture = load_fixture();
        let source = build_source(&fixture);
        let root = tempfile::tempdir().expect("tempdir");
        let (path, artifact) = produce(
            &source,
            &fixture,
            Network::Regtest,
            root.path(),
            "twice.dat",
        );
        let base = base_at_tip(&fixture);
        let manifest = target(&path, base, artifact.sha256, artifact.bytes);

        let (receiver_store, receiver) = empty_receiver();
        attach_compact_filter_artifact(
            &receiver,
            &manifest,
            root.path(),
            &SpillBudget::new(u64::MAX),
        )
        .expect("the first attach succeeds");
        let before = rows_with_prefix(&receiver_store, ColumnFamily::Filters, &[]);
        assert_eq!(
            before,
            fixture.hashes.len(),
            "the first attach stores one height-keyed row per block"
        );

        let error = attach_compact_filter_artifact(
            &receiver,
            &manifest,
            root.path(),
            &SpillBudget::new(u64::MAX),
        )
        .expect_err("a populated CompactFilters family refuses a second attach");
        assert!(
            matches!(
                error,
                IndexBundleError::Index(IndexError::WatermarkMismatch { .. })
            ),
            "got {error:?}"
        );
        assert_eq!(
            rows_with_prefix(&receiver_store, ColumnFamily::Filters, &[]),
            before,
            "the refused attach leaves the rows as they were"
        );
    }

    // SNP-02
    #[test]
    fn compact_filter_artifact_nonzero_floor_is_refused_without_rows() {
        let fixture = load_fixture();
        let source = build_source(&fixture);
        let root = tempfile::tempdir().expect("tempdir");
        let (path, artifact) = produce(
            &source,
            &fixture,
            Network::Regtest,
            root.path(),
            "floor.dat",
        );
        let mut raised = target(
            &path,
            base_at_tip(&fixture),
            artifact.sha256,
            artifact.bytes,
        );
        raised.floor = 1;

        let (receiver_store, receiver) = empty_receiver();
        let error = attach_compact_filter_artifact(
            &receiver,
            &raised,
            root.path(),
            &SpillBudget::new(u64::MAX),
        )
        .expect_err("a compact filter floor above zero is refused");
        assert!(
            matches!(error, IndexBundleError::ArtifactHeader { .. }),
            "got {error:?}"
        );
        assert_untouched(&receiver_store, &receiver);
    }
}
mod compact_filters {
    use crate::support::{TestError, common};

    use bitcoin::{Block, consensus::serialize, hashes::Hash as _};
    use bitcoin_rs_projection::{
        ConsumerCursorUpdate, IndexCapabilities, IndexError, IndexReader, IndexWatermark,
        IndexWriter, PreparedBatch, PreparedBatchLimits, SpentCoin, SpentCoins,
    };
    use bitcoin_rs_storage::KvStore;
    use std::sync::{Arc, atomic::Ordering};

    struct NoSpends;
    impl SpentCoins for NoSpends {
        fn spent_coin(&self, _: &[u8; 32], _: u32) -> Option<SpentCoin<'_>> {
            None
        }
    }

    fn prepare<S: KvStore>(
        writer: &IndexWriter<S>,
        block: &Block,
        height: u32,
        caps: IndexCapabilities,
    ) -> Result<PreparedBatch, IndexError> {
        let block = writer.prepare_block_with_spent_scripts(
            caps,
            height,
            block.block_hash().to_byte_array(),
            &serialize(block),
            &NoSpends,
        )?;
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: 100,
            max_bytes: 10_000,
        });
        assert!(batch.try_push(block).is_ok());
        Ok(batch)
    }

    // IDX-04
    #[test]
    fn filter_rows_and_cursor_publish_atomically_and_reset_preserves_txindex()
    -> Result<(), TestError> {
        let store = Arc::new(common::MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        assert!(matches!(
            writer.prepare_block_for(
                IndexCapabilities::COMPACT_FILTERS,
                0,
                genesis.block_hash().to_byte_array(),
                &serialize(&genesis)
            ),
            Err(IndexError::MissingSpentScripts)
        ));
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Testnet);
        let hash = genesis.block_hash().to_byte_array();
        let caps = IndexCapabilities::TX_LOOKUP.with_compact_filters(true);
        store.fail_next_fenced_write.store(true, Ordering::SeqCst);
        assert!(matches!(
            writer.commit_forward(prepare(&writer, &genesis, 0, caps)?),
            Err(IndexError::Storage(_))
        ));
        assert!(writer.watermarks()?.compact_filters.is_none());
        assert!(writer.snapshot()?.compact_filter(0, &hash)?.is_none());
        writer.commit_forward(prepare(&writer, &genesis, 0, caps)?)?;
        let original = writer
            .snapshot()?
            .compact_filter(0, &hash)?
            .ok_or("missing filter")?;
        assert_eq!(original.filter, [1, 0x9d, 0xfc, 0xa8]);
        let mark = Some(IndexWatermark { height: 0, hash });
        assert_eq!(writer.watermarks()?.compact_filters, mark);

        let mut child = genesis.clone();
        child.header.prev_blockhash = genesis.block_hash();
        child.header.nonce = child.header.nonce.wrapping_add(1);
        let stale_batch = prepare(&writer, &child, 1, IndexCapabilities::COMPACT_FILTERS)?;
        let stale_fence = writer.fenced_watermarks()?.0;
        writer.reset_capabilities(IndexCapabilities::COMPACT_FILTERS)?;
        assert_eq!(writer.watermarks()?.tx_lookup, mark);
        assert!(writer.snapshot()?.compact_filter(0, &hash)?.is_none());
        assert!(matches!(
            writer.commit_forward_with_cursor(stale_fence, stale_batch, ConsumerCursorUpdate::Keep),
            Err(IndexError::ResetInProgress)
        ));

        writer.commit_forward(prepare(
            &writer,
            &genesis,
            0,
            IndexCapabilities::COMPACT_FILTERS,
        )?)?;
        writer.commit_forward(prepare(
            &writer,
            &child,
            1,
            IndexCapabilities::COMPACT_FILTERS,
        )?)?;
        let fence = writer.fenced_watermarks()?.0;
        assert!(matches!(
            writer.commit_rollback_one_for_with_cursor(
                fence,
                IndexCapabilities::COMPACT_FILTERS,
                mark,
                &serialize(&child),
                ConsumerCursorUpdate::Keep,
            ),
            Err(IndexError::MissingSpentScripts)
        ));
        writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            IndexCapabilities::COMPACT_FILTERS,
            mark,
            &serialize(&child),
            ConsumerCursorUpdate::Keep,
            &NoSpends,
        )?;
        assert!(
            writer
                .snapshot()?
                .compact_filter(1, &child.block_hash().to_byte_array())?
                .is_none()
        );
        assert_eq!(
            writer.snapshot()?.compact_filter(0, &hash)?,
            Some(original.clone())
        );
        drop(writer);
        let reopened = IndexWriter::open(store, 2)?;
        assert_eq!(reopened.watermarks()?.compact_filters, mark);
        assert_eq!(
            reopened.snapshot()?.compact_filter(0, &hash)?,
            Some(original)
        );
        Ok(())
    }

    #[test]
    fn compact_filters_survive_rocksdb_index_reopen() -> Result<(), TestError> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("index");
        let block = bitcoin::constants::genesis_block(bitcoin::Network::Testnet);
        let hash = block.block_hash().to_byte_array();
        {
            let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open(&path)?);
            let mut writer = IndexWriter::open(store, 1)?;
            writer.commit_forward(prepare(
                &writer,
                &block,
                0,
                IndexCapabilities::COMPACT_FILTERS,
            )?)?;
        }
        let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open(&path)?);
        let writer = IndexWriter::open(store, 2)?;
        assert_eq!(
            writer
                .snapshot()?
                .compact_filter(0, &hash)?
                .ok_or("missing filter")?
                .filter,
            [1, 0x9d, 0xfc, 0xa8]
        );
        Ok(())
    }
}
mod generation_parity {
    use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid};
    use bitcoin_rs_projection::segment::bulk_builder::{
        BulkSegmentBuilder, StreamingSegmentBuilder,
    };
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
    use bitcoin_rs_storage::committed_facts::{
        CommittedBlock, CreatedOutput, SpentPrevout, TxFacts,
    };
    use bitcoin_rs_storage::{
        ColumnFamily, FactsScript, KvStore, PrefixScanLimit, RocksDbStore, StorageError,
    };
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use tempfile::tempdir;

    use crate::support::TestError;

    const SEGMENT_FAMILIES: [ColumnFamily; 6] = [
        ColumnFamily::TxDir,
        ColumnFamily::ScriptDict,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptStats,
        ColumnFamily::Filters,
    ];

    const SCAN_ALL: PrefixScanLimit = PrefixScanLimit {
        max_rows: 100_000,
        max_bytes: 64 << 20,
    };

    fn cross_block_script(height: u32) -> FactsScript {
        let mut script = b"\x76\xa9\x14cross_block_spent_\x88\xac".to_vec();
        script[15] = u8::try_from(height & 0xff).unwrap_or(0);
        FactsScript::copy_from_slice(&script)
    }

    fn self_transfer_script(height: u32) -> FactsScript {
        let mut script = b"\x76\xa9\x14self_transfer_script\x88\xac".to_vec();
        script[16] = u8::try_from(height & 0xff).unwrap_or(0);
        FactsScript::copy_from_slice(&script)
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
                        script: FactsScript::copy_from_slice(
                            b"\x76\xa9\x14synthetic_prev_script\x88\xac",
                        ),
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
                            FactsScript::copy_from_slice(
                                b"\x76\xa9\x14synthetic_output_script\x88\xac",
                            )
                        },
                    },
                    CreatedOutput {
                        vout: 1,
                        value: 25_000,
                        script: FactsScript::copy_from_slice(b"\x00\x14synthetic_witness_script"),
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
        for pair in tail_seal_and_bulk_family_digests(&blocks, 1)? {
            assert!(pair.tail_rows > 0, "{:?} has no sealed rows", pair.family);
            assert_eq!(
                pair.tail_rows, pair.bulk_rows,
                "{:?} row count differs between tail and bulk",
                pair.family
            );
            assert_eq!(pair.tail, pair.bulk, "mismatch on {:?}", pair.family);
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
        let funded_script = FactsScript::copy_from_slice(b"\x76\xa9\x14fresh_output\x88\xac");
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
                        script: FactsScript::copy_from_slice(b"\x76\xa9\x14spent_output\x88\xac"),
                    }],
                }],
            },
        ]
    }

    fn append_tail_blocks<S: KvStore>(
        store: &S,
        blocks: &[CommittedBlock],
    ) -> Result<(), TestError> {
        let mut tail_state = TailWriterState::new();
        for block in blocks {
            let mut batch = store.new_batch();
            append_tail_block(&mut batch, block, &mut tail_state, &NoSealedTxOrdinals)?;
            store.write_durable(batch)?;
        }
        Ok(())
    }

    fn tail_seal_and_bulk_family_digests(
        blocks: &[CommittedBlock],
        gen_id: u64,
    ) -> Result<Vec<FamilyDigestPair>, TestError> {
        let dir_tail = tempdir()?;
        let scratch_tail = tempdir()?;
        let store_tail = RocksDbStore::open(dir_tail.path())?;
        append_tail_blocks(&store_tail, blocks)?;
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
        for &cf in &SEGMENT_FAMILIES {
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
                        script: FactsScript::default(),
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
                        script: FactsScript::default(),
                        height: 1,
                        coinbase: false,
                    }],
                    outputs: vec![CreatedOutput {
                        vout: 0,
                        value: 19_000,
                        script: FactsScript::copy_from_slice(b"\x51"),
                    }],
                }],
            },
        ];
        let empty_script_hash = ScriptHash::from_byte_array(Sha256::digest(b"").into());

        let live_pairs = {
            let dir = tempdir()?;
            let scratch = tempdir()?;
            let store = Arc::new(RocksDbStore::open(dir.path())?);
            append_tail_blocks(store.as_ref(), &blocks)?;
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
        use bitcoin_rs_projection::segment::format::{
            decode_posting_items, decode_script_post_key,
        };
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
                            script: FactsScript::copy_from_slice(&[0x51]),
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
        let mut writer =
            bitcoin_rs_projection::IndexWriter::open(std::sync::Arc::clone(&store), 1)?
                .with_seal_scratch(scratch.path().to_path_buf());
        let prepared = writer
            .prepare_block_from_facts(IndexCapabilities::ALL, one_script_block(occurrences))?;
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
        let mut digests = Vec::new();
        for &cf in &SEGMENT_FAMILIES {
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

    fn p2wpkh_script(tag: u32) -> FactsScript {
        let mut script = vec![0x00u8, 0x14];
        script.extend_from_slice(&tag.to_le_bytes());
        script.extend_from_slice(&[0x11u8; 16]);
        FactsScript::copy_from_slice(&script)
    }

    fn p2tr_script(tag: u32) -> FactsScript {
        let mut script = vec![0x51u8, 0x20];
        script.extend_from_slice(&tag.to_le_bytes());
        script.extend_from_slice(&[0x22u8; 28]);
        FactsScript::copy_from_slice(&script)
    }

    fn same_block_script(tag: u32) -> FactsScript {
        let mut script = vec![0x00u8, 0x20];
        script.extend_from_slice(&tag.to_le_bytes());
        script.extend_from_slice(&[0x33u8; 26]);
        FactsScript::copy_from_slice(&script)
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
        scripts: Vec<FactsScript>,
        spent: Vec<([u8; 32], u32)>,
    }

    fn create_spend_chain(count: u32) -> SpendChain {
        let mut blocks = Vec::new();
        let mut seen = BTreeSet::new();
        let mut scripts = Vec::new();
        let mut spent = Vec::new();
        let mut remember = |script: FactsScript| {
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
        let next_ordinal =
            u32::try_from(blocks.iter().map(|block| block.txs.len()).sum::<usize>())?;
        bitcoin_rs_projection::segment::publish_bulk_generation(
            store,
            gen_id,
            coverage,
            next_ordinal,
            IndexCapabilities::ALL,
        )?;
        Ok(())
    }

    fn count_rows<S: KvStore>(
        store: &S,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<u64, TestError> {
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
        for &cf in &SEGMENT_FAMILIES {
            out.push((cf, count_rows(store, cf, &[])?));
        }
        out.push((
            ColumnFamily::IdxMeta,
            count_rows(store, ColumnFamily::IdxMeta, &[])?,
        ));
        Ok(out)
    }

    fn gen_zero_totals<S: KvStore>(store: &S) -> Result<Vec<(ColumnFamily, u64)>, TestError> {
        let prefix = 0u64.to_be_bytes();
        let mut out = Vec::new();
        for &cf in &SEGMENT_FAMILIES {
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
            batch.try_push(prepared).map_err(|_| {
                TestError::Message("catch-up batch must admit the block".to_owned())
            })?;
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
        append_tail_blocks(live.as_ref(), &chain.blocks)?;
        seal_tail_generation(
            live.as_ref(),
            GEN_ID,
            coverage.last_height,
            caps,
            scratch_live.path(),
        )?;
        for &cf in &SEGMENT_FAMILIES {
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

        fn delete_range(
            &self,
            cf: ColumnFamily,
            start: &[u8],
            end: &[u8],
        ) -> Result<(), StorageError> {
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
}
mod index_roundtrip {
    use crate::support::{TestError, common};

    use common::MemoryStore;
    use std::{
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use bitcoin_rs_consensus::primitives::{
        Block, DecodeError, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid,
        Witness, consensus_bytes, deserialize, encode::double_sha256,
    };
    use parking_lot::{Mutex, RwLock};

    use bitcoin_rs_projection::CURSOR_BYTE_LEN;
    use bitcoin_rs_projection::ScriptHash;
    use bitcoin_rs_projection::types::{
        HEADER_ROW_SIZE, ScriptHistoryOccurrence, TxPosition, TxPositionValue,
    };
    use bitcoin_rs_projection::{
        ConsumerCursorUpdate, IndexCapabilities, IndexError, IndexReader, IndexWatermark,
        IndexWatermarks, IndexWriter, Indexer, PreparedBatch, PreparedBatchLimits, PreparedBlock,
        SpentCoin, SpentCoins,
    };
    use bitcoin_rs_storage::{
        BatchOp, BufferedWriteBatch, ColumnFamily, KvIter, KvSnapshot, KvStore, PrefixScan,
        PrefixScanLimit, StorageError, WriteCondition,
    };

    const RESET_KEY: &[u8] = &[0x00, b'R'];

    struct FixtureScripts;

    static FIXTURE_SPENT_SCRIPT: [u8; 2] = [0x51, 0x01];

    impl SpentCoins for FixtureScripts {
        fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
            Some(SpentCoin {
                script: FIXTURE_SPENT_SCRIPT.as_slice(),
                value: 0,
                height: 0,
                coinbase: false,
            })
        }
    }

    fn prepare<S: KvStore>(
        writer: &IndexWriter<S>,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        writer.prepare_block_with_spent_scripts(
            IndexCapabilities::HISTORICAL,
            height,
            hash,
            body,
            &FixtureScripts,
        )
    }

    fn prepare_for<S: KvStore>(
        writer: &IndexWriter<S>,
        capabilities: IndexCapabilities,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        writer.prepare_block_with_spent_scripts(capabilities, height, hash, body, &FixtureScripts)
    }

    fn commit_block<S: KvStore>(
        writer: &mut IndexWriter<S>,
        height: u32,
        body: &[u8],
    ) -> Result<IndexWatermark, IndexError> {
        let header = body
            .get(..HEADER_ROW_SIZE)
            .ok_or(IndexError::InvalidHeaderLength { len: body.len() })?;
        let hash = double_sha256(header).to_le_bytes();
        let prepared = prepare(writer, height, hash, body)?;
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        assert!(batch.try_push(prepared).is_ok(), "one block is admitted");
        writer.commit_forward(batch)
    }

    fn commit_rollback_one_for<S: KvStore>(
        writer: &mut IndexWriter<S>,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
    ) -> Result<(), IndexError> {
        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            capabilities,
            prev,
            body,
            ConsumerCursorUpdate::Clear,
            &FixtureScripts,
        )
    }

    const ORDINARY_STATE_REVISION_KEY: &[u8] = &[0x00, b'O'];

    fn claim_bytes(mask: u8, process_epoch: u64, base_version: u64) -> Vec<u8> {
        let mut value = Vec::with_capacity(17);
        value.push(mask);
        value.extend_from_slice(&process_epoch.to_le_bytes());
        value.extend_from_slice(&base_version.to_le_bytes());
        value
    }

    fn idle_bytes(version: u64) -> Vec<u8> {
        let mut value = Vec::with_capacity(9);
        value.push(0xFF);
        value.extend_from_slice(&version.to_le_bytes());
        value
    }

    fn is_idle_marker(bytes: &[u8]) -> bool {
        bytes.len() == idle_bytes(0).len() && bytes[0] == 0xFF
    }

    fn decode_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes.get(offset..offset + 8)?);
        Some(u64::from_le_bytes(arr))
    }

    fn stored_idle_version<S: KvStore>(store: &Arc<S>) -> Result<u64, TestError> {
        match store.get(ColumnFamily::UtxoMeta, RESET_KEY)? {
            Some(bytes) if is_idle_marker(&bytes) => Ok(decode_u64_le(&bytes, 1)
                .ok_or_else(|| std::io::Error::other("idle marker truncated"))?),
            other => {
                Err(std::io::Error::other(format!("reset state is not idle: {other:?}")).into())
            }
        }
    }

    fn tail_log_keys<S: KvStore>(store: &Arc<S>) -> Result<Vec<Vec<u8>>, TestError> {
        let mut keys = Vec::new();
        for item in store.iter_prefix(ColumnFamily::IdxMeta, b"tail/log/")? {
            let (key, _) = item?;
            keys.push(key);
        }
        Ok(keys)
    }

    #[derive(Clone, Debug)]
    struct BatchLog {
        durable: bool,
        marker_put: Option<Vec<u8>>,
        deletes: usize,
    }

    #[derive(Default)]
    struct CallTrackingStore {
        inner: MemoryStore,
        writes: AtomicUsize,
        durable_writes: AtomicUsize,
        flushes: AtomicUsize,
        batches: RwLock<Vec<BatchLog>>,
        read_order: Mutex<Vec<(ColumnFamily, Vec<u8>)>>,
        snapshot_read_order: Mutex<Vec<(ColumnFamily, Vec<u8>)>>,
        snapshots: AtomicUsize,
        snapshot_reset_after_tx_watermark_read: Mutex<Option<(u64, u64)>>,
        snapshot_reset_after_revision_read: Mutex<Option<(u64, u64)>>,
        cursor_race_tx_watermark: Mutex<Option<IndexWatermark>>,
        fence_reset_during_header_read: Mutex<Option<(u64, u64)>>,
        cursor_race_script_watermark: Mutex<Option<IndexWatermark>>,
    }

    impl CallTrackingStore {
        fn count(&self, cf: ColumnFamily) -> usize {
            self.inner.count(cf)
        }

        fn logged_batches(&self) -> Vec<BatchLog> {
            self.batches.read().clone()
        }

        fn advance_fence_and_clear_index_state(
            &self,
            next_version: u64,
            next_revision: u64,
        ) -> Result<(), StorageError> {
            let mut batch = self.inner.new_batch();
            batch.put(ColumnFamily::UtxoMeta, RESET_KEY, &idle_bytes(next_version));
            batch.put(
                ColumnFamily::UtxoMeta,
                ORDINARY_STATE_REVISION_KEY,
                &next_revision.to_le_bytes(),
            );
            batch.delete(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY);
            batch.delete(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY);
            batch.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
            self.inner.write(batch)
        }

        fn build_log(ops: &[BatchOp], durable: bool) -> BatchLog {
            let mut entry = BatchLog {
                durable,
                marker_put: None,
                deletes: 0,
            };
            for op in ops {
                match op {
                    BatchOp::Put { cf, key, value }
                        if *cf == ColumnFamily::UtxoMeta && key.as_slice() == RESET_KEY =>
                    {
                        entry.marker_put = Some(value.to_vec());
                    }
                    BatchOp::Delete { .. } | BatchOp::DeleteRange { .. } => entry.deletes += 1,
                    BatchOp::Put { .. } => {}
                }
            }
            entry
        }
    }

    impl KvStore for CallTrackingStore {
        fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.read_order.lock().push((cf, key.to_vec()));
            if cf == ColumnFamily::BlockHeaders {
                let reset = self.fence_reset_during_header_read.lock().take();
                if let Some((next_version, next_revision)) = reset {
                    self.advance_fence_and_clear_index_state(next_version, next_revision)?;
                }
            }
            self.inner.get(cf, key)
        }

        fn iter_prefix<'a>(
            &'a self,
            cf: ColumnFamily,
            prefix: &[u8],
        ) -> Result<KvIter<'a>, StorageError> {
            self.inner.iter_prefix(cf, prefix)
        }

        fn scan_prefix_from_bounded(
            &self,
            cf: ColumnFamily,
            prefix: &[u8],
            start: &[u8],
            limit: PrefixScanLimit,
        ) -> Result<PrefixScan, StorageError> {
            self.inner
                .scan_prefix_from_bounded(cf, prefix, start, limit)
        }

        fn new_batch(&self) -> BufferedWriteBatch {
            self.inner.new_batch()
        }

        fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            let ops = batch.into_ops();
            let entry = Self::build_log(&ops, false);
            self.inner.write(restore_batch(ops))?;
            self.batches.write().push(entry);
            Ok(())
        }

        fn write_durable(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
            self.durable_writes.fetch_add(1, Ordering::Relaxed);
            let ops = batch.into_ops();
            let entry = Self::build_log(&ops, true);
            self.inner.write(restore_batch(ops))?;
            self.batches.write().push(entry);
            Ok(())
        }

        fn write_durable_if(
            &self,
            conditions: &[WriteCondition<'_>],
            batch: BufferedWriteBatch,
        ) -> Result<bool, StorageError> {
            let ops = batch.into_ops();
            let entry = Self::build_log(&ops, true);
            if put_value_of(&ops, ColumnFamily::UtxoMeta, CURSOR_KEY).is_some() {
                let tx_watermark = self.cursor_race_tx_watermark.lock().take();
                if let Some(watermark) = tx_watermark {
                    self.inner.put(
                        ColumnFamily::UtxoMeta,
                        TX_WATERMARK_KEY,
                        &watermark.to_bytes(),
                    )?;
                }
                let script_watermark = self.cursor_race_script_watermark.lock().take();
                if let Some(watermark) = script_watermark {
                    self.inner.put(
                        ColumnFamily::UtxoMeta,
                        SCRIPT_WATERMARK_KEY,
                        &watermark.to_bytes(),
                    )?;
                }
            }
            let applied = self
                .inner
                .write_durable_if(conditions, restore_batch(ops))?;
            if applied {
                self.durable_writes.fetch_add(1, Ordering::Relaxed);
                self.batches.write().push(entry);
            }
            Ok(applied)
        }

        fn flush(&self) -> Result<(), StorageError> {
            self.flushes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
            self.snapshots.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(CallTrackingSnapshot {
                captured: self.inner.snapshot()?,
                store: self,
            }))
        }

        fn arm_persist_fault(&self, _fault: bitcoin_rs_storage::PersistFault) {}

        fn multi_get(
            &self,
            cf: ColumnFamily,
            keys: &[&[u8]],
        ) -> Result<Vec<Option<bitcoin_rs_storage::Bytes>>, StorageError> {
            keys.iter()
                .map(|key| {
                    self.get(cf, key)
                        .map(|opt| opt.map(bitcoin_rs_storage::Bytes::from))
                })
                .collect()
        }

        fn ingest_sorted(
            &self,
            cf: ColumnFamily,
            rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
            scratch: &std::path::Path,
        ) -> Result<u64, StorageError> {
            self.inner.ingest_sorted(cf, rows, scratch)
        }

        fn delete_range(
            &self,
            cf: ColumnFamily,
            start: &[u8],
            end: &[u8],
        ) -> Result<(), StorageError> {
            self.inner.delete_range(cf, start, end)
        }

        fn checkpoint(&self, dir: &std::path::Path) -> Result<(), StorageError> {
            self.inner.checkpoint(dir)
        }

        fn engine_cache_bytes(&self) -> u64 {
            self.inner.engine_cache_bytes()
        }
    }

    struct CallTrackingSnapshot<'a> {
        captured: Box<dyn KvSnapshot + 'a>,
        store: &'a CallTrackingStore,
    }

    impl KvSnapshot for CallTrackingSnapshot<'_> {
        fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            let observed = self.captured.get(cf, key)?;
            self.store
                .snapshot_read_order
                .lock()
                .push((cf, key.to_vec()));
            if cf == ColumnFamily::UtxoMeta && key == ORDINARY_STATE_REVISION_KEY {
                let reset = self.store.snapshot_reset_after_revision_read.lock().take();
                if let Some((next_version, next_revision)) = reset {
                    self.store
                        .advance_fence_and_clear_index_state(next_version, next_revision)?;
                }
            }
            if cf == ColumnFamily::UtxoMeta && key == TX_WATERMARK_KEY {
                let reset = self
                    .store
                    .snapshot_reset_after_tx_watermark_read
                    .lock()
                    .take();
                if let Some((next_version, next_revision)) = reset {
                    self.store
                        .advance_fence_and_clear_index_state(next_version, next_revision)?;
                }
            }
            if cf == ColumnFamily::BlockHeaders {
                let reset = self.store.fence_reset_during_header_read.lock().take();
                if let Some((next_version, next_revision)) = reset {
                    self.store
                        .advance_fence_and_clear_index_state(next_version, next_revision)?;
                }
            }
            Ok(observed)
        }

        fn iter_prefix<'a>(
            &'a self,
            cf: ColumnFamily,
            prefix: &[u8],
        ) -> Result<KvIter<'a>, StorageError> {
            self.captured.iter_prefix(cf, prefix)
        }

        fn scan_prefix_from_bounded(
            &self,
            cf: ColumnFamily,
            prefix: &[u8],
            start: &[u8],
            limit: PrefixScanLimit,
        ) -> Result<PrefixScan, StorageError> {
            self.captured
                .scan_prefix_from_bounded(cf, prefix, start, limit)
        }
    }

    fn put_value_of(ops: &[BatchOp], cf: ColumnFamily, key: &[u8]) -> Option<Vec<u8>> {
        ops.iter().find_map(|op| match op {
            BatchOp::Put {
                cf: op_cf,
                key: op_key,
                value,
            } if *op_cf == cf && op_key.as_slice() == key => Some(value.to_vec()),
            _ => None,
        })
    }

    fn deletes_derived_rows(ops: &[BatchOp]) -> bool {
        ops.iter().any(|op| {
            matches!(
                op,
                BatchOp::Delete { cf, .. } | BatchOp::DeleteRange { cf, .. }
                    if *cf != ColumnFamily::UtxoMeta
            )
        })
    }

    fn restore_batch(ops: Vec<BatchOp>) -> BufferedWriteBatch {
        let mut batch = BufferedWriteBatch::default();
        for op in ops {
            match op {
                BatchOp::Put { cf, key, value } => batch.put_value(cf, &key, value),
                BatchOp::Delete { cf, key } => batch.delete(cf, &key),
                BatchOp::DeleteRange { cf, start, end } => batch.delete_range(cf, &start, &end),
            }
        }
        batch
    }

    // IDX-09
    #[test]
    fn commit_golden_blocks_writes_expected_electrs_rows() -> Result<(), TestError> {
        for height in [0_u32, 170, 481_824] {
            let store = Arc::new(MemoryStore::default());
            let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
            let body = read_fixture(height)?;
            let block = deserialize::<Block>(&body)?;
            let facts = golden_facts(&block);

            commit_block(&mut writer, 0, &body)?;
            let indexer = Indexer::new(Arc::clone(&store));
            assert_one_tx_row_each(&indexer, &block, height)?;

            let mut scripts = facts.funding_scripts.clone();
            scripts.insert(FIXTURE_SPENT_SCRIPT.to_vec());
            let totals = history_totals(&indexer, &scripts, &facts.funding_scripts)?;
            assert_eq!(
                totals.unfunded_scripts, 0,
                "height {height} keeps at least one row per funding script"
            );
            assert_eq!(
                totals.funding, facts.funding_outputs,
                "height {height} writes one funding occurrence per output"
            );
            assert_eq!(
                totals.spending, facts.spending_inputs,
                "height {height} writes one spending occurrence per non-coinbase input"
            );
            assert_eq!(
                spent_row_count(&indexer, &block)?,
                facts.in_block_spends,
                "height {height} spender rows name only in-block creations"
            );
        }
        Ok(())
    }

    fn read_fixture(height: u32) -> Result<Vec<u8>, std::io::Error> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/consensus/blocks")
            .join(format!("{height}.bin"));
        std::fs::read(path)
    }

    fn block_hash(body: &[u8]) -> [u8; 32] {
        double_sha256(&body[..80]).to_le_bytes()
    }

    fn parent_hash(body: &[u8]) -> [u8; 32] {
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&body[4..36]);
        hash
    }

    const ROW_LIMIT: PrefixScanLimit = PrefixScanLimit {
        max_rows: 10,
        max_bytes: 1_024,
    };

    const SCAN_ALL: PrefixScanLimit = PrefixScanLimit {
        max_rows: 100_000,
        max_bytes: 64 << 20,
    };

    fn coinbase_txid(body: &[u8]) -> Result<Txid, TestError> {
        Ok(deserialize::<Block>(body)?.txs[0].txid())
    }

    fn coinbase_scripthash(body: &[u8]) -> Result<ScriptHash, TestError> {
        let block = deserialize::<Block>(body)?;
        Ok(ScriptHash::new(
            block.txs[0].outputs[0].script_pubkey.as_bytes(),
        ))
    }

    fn tx_row_count<S: KvStore>(store: &Arc<S>, txid: &Txid) -> Result<usize, TestError> {
        let indexer = Indexer::new(Arc::clone(store));
        let snapshot = indexer.snapshot()?;
        Ok(snapshot.transaction_rows(txid, ROW_LIMIT)?.rows.len())
    }

    fn funding_row_count<S: KvStore>(
        store: &Arc<S>,
        scripthash: ScriptHash,
    ) -> Result<usize, TestError> {
        let indexer = Indexer::new(Arc::clone(store));
        let snapshot = indexer.snapshot()?;
        Ok(snapshot.funding_rows(scripthash, SCAN_ALL)?.rows.len())
    }

    struct GoldenFacts {
        funding_outputs: usize,
        funding_scripts: std::collections::BTreeSet<Vec<u8>>,
        spending_inputs: usize,
        in_block_spends: usize,
    }

    fn golden_facts(block: &Block) -> GoldenFacts {
        let mut facts = GoldenFacts {
            funding_outputs: 0,
            funding_scripts: std::collections::BTreeSet::new(),
            spending_inputs: 0,
            in_block_spends: 0,
        };
        let mut earlier_txids: std::collections::BTreeSet<[u8; 32]> =
            std::collections::BTreeSet::new();
        for tx in &block.txs {
            if !tx.is_coinbase() {
                facts.spending_inputs += tx.inputs.len();
                facts.in_block_spends += tx
                    .inputs
                    .iter()
                    .filter(|input| earlier_txids.contains(input.previous_output.txid.as_bytes()))
                    .count();
            }
            for output in &tx.outputs {
                let script = output.script_pubkey.as_bytes();
                if !script.is_empty() && script[0] != 0x6a {
                    facts.funding_outputs += 1;
                    facts.funding_scripts.insert(script.to_vec());
                }
            }
            earlier_txids.insert(*tx.txid().as_bytes());
        }
        facts
    }

    #[derive(Default)]
    struct HistoryTotals {
        funding: usize,
        spending: usize,
        unfunded_scripts: usize,
    }

    fn add_occurrences(totals: &mut HistoryTotals, value: &[u8]) -> Result<(), TestError> {
        let occurrences =
            ScriptHistoryOccurrence::decode_all(value).ok_or("funding rows carry occurrences")?;
        for occurrence in occurrences {
            if occurrence.flags & ScriptHistoryOccurrence::FUNDING != 0 {
                totals.funding += 1;
            }
            if occurrence.flags & ScriptHistoryOccurrence::SPENDING != 0 {
                totals.spending += 1;
            }
        }
        Ok(())
    }

    fn history_totals(
        indexer: &Indexer<MemoryStore>,
        scripts: &std::collections::BTreeSet<Vec<u8>>,
        funded: &std::collections::BTreeSet<Vec<u8>>,
    ) -> Result<HistoryTotals, TestError> {
        let snapshot = indexer.snapshot()?;
        let mut totals = HistoryTotals::default();
        for script in scripts {
            let rows = snapshot.funding_rows(ScriptHash::from_script_bytes(script), SCAN_ALL)?;
            assert!(rows.complete, "occurrence scan is complete");
            if funded.contains(script) && rows.rows.is_empty() {
                totals.unfunded_scripts += 1;
            }
            for row in &rows.rows {
                add_occurrences(&mut totals, &row.value)?;
            }
        }
        Ok(totals)
    }

    fn assert_one_tx_row_each(
        indexer: &Indexer<MemoryStore>,
        block: &Block,
        height: u32,
    ) -> Result<(), TestError> {
        let snapshot = indexer.snapshot()?;
        for tx in &block.txs {
            let rows = snapshot.transaction_rows(&tx.txid(), ROW_LIMIT)?;
            assert_eq!(rows.rows.len(), 1, "height {height} txid row");
        }
        Ok(())
    }

    fn spent_row_count(indexer: &Indexer<MemoryStore>, block: &Block) -> Result<usize, TestError> {
        let snapshot = indexer.snapshot()?;
        let mut count = 0_usize;
        for tx in block.txs.iter().filter(|tx| !tx.is_coinbase()) {
            for input in &tx.inputs {
                count += snapshot
                    .spending_rows(&input.previous_output, ROW_LIMIT)?
                    .rows
                    .len();
            }
        }
        Ok(count)
    }

    #[test]
    fn watermark_bytes_round_trip_and_truncation_is_rejected() -> Result<(), TestError> {
        let watermark = IndexWatermark {
            height: 123,
            hash: [0xab; 32],
        };
        let bytes = watermark.to_bytes();
        assert_eq!(IndexWatermark::from_bytes(&bytes)?, watermark);
        assert!(matches!(
            IndexWatermark::from_bytes(&bytes[..3]),
            Err(IndexError::InvalidWatermark)
        ));

        let store = Arc::new(MemoryStore::default());
        store.put(
            ColumnFamily::UtxoMeta,
            &[0x00, b'V'],
            &bitcoin_rs_projection::INDEX_FORMAT_VERSION_VALUE,
        )?;
        store.put(ColumnFamily::UtxoMeta, &[0x00, b'T'], &[0_u8; 2])?;
        assert!(matches!(
            IndexWriter::open(store, 1)?.watermark(),
            Err(IndexError::InvalidWatermark)
        ));
        Ok(())
    }

    #[test]
    fn open_rejects_incompatible_durable_metadata() -> Result<(), TestError> {
        let cases: [(&str, Option<&[u8]>); 3] = [
            ("format 4", Some(&[4, 0, 0, 0])),
            ("format 4 with a trailing byte", Some(&[4, 0, 0, 0, 0])),
            ("derived rows with no version cell", None),
        ];
        for (label, version) in cases {
            let store = Arc::new(MemoryStore::default());
            match version {
                Some(version) => store.put(ColumnFamily::UtxoMeta, &[0x00, b'V'], version)?,
                None => store.put(ColumnFamily::TxDir, b"orphan-row", &[])?,
            }
            let failure = IndexWriter::open(store, 1).err();
            if version.is_some() {
                assert!(
                    matches!(
                        failure,
                        Some(IndexError::UnsupportedTxIndexFormatVersion { version: 4 })
                    ),
                    "{label}"
                );
            } else {
                assert!(
                    matches!(failure, Some(IndexError::LegacyCursorlessIndex)),
                    "{label}"
                );
            }
        }
        Ok(())
    }
    // RCV-11
    #[test]
    fn format_4_open_refuses_for_rebuild() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        seed_populated_store(&store, 1)?;
        store.put(ColumnFamily::UtxoMeta, &[0x00, b'V'], &4_u32.to_le_bytes())?;
        assert!(matches!(
            IndexWriter::open(Arc::clone(&store), 1),
            Err(IndexError::UnsupportedTxIndexFormatVersion { version: 4 })
        ));

        IndexWriter::reset_index(store.as_ref(), 1)?;
        assert!(
            IndexWriter::open(Arc::clone(&store), 1)?
                .watermark()?
                .is_none()
        );
        assert_eq!(
            store.count(ColumnFamily::TxDir),
            0,
            "derived rows are removed by the rebuild"
        );
        Ok(())
    }

    // RCV-11
    #[test]
    fn reset_index_replaces_an_incompatible_derived_format() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        store.put(
            bitcoin_rs_storage::ColumnFamily::UtxoMeta,
            &[0x00, b'V'],
            &2_u32.to_le_bytes(),
        )?;
        store.put(bitcoin_rs_storage::ColumnFamily::TxDir, b"old", b"row")?;

        IndexWriter::reset_index(store.as_ref(), 1)?;

        assert!(
            IndexWriter::open(Arc::clone(&store), 1)?
                .watermark()?
                .is_none()
        );
        assert_eq!(
            store.count(bitcoin_rs_storage::ColumnFamily::TxDir),
            0,
            "derived rows are removed by the rebuild"
        );
        Ok(())
    }

    #[test]
    fn prepare_block_verifies_header_identity_and_parent() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        let writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let body = read_fixture(0)?;
        let hash = block_hash(&body);

        let block = prepare(&writer, 0, hash, &body)?;
        assert_eq!(block.height, 0);
        assert_eq!(block.hash, hash);
        assert_eq!(block.parent_hash, [0u8; 32]);
        assert_eq!(block.row_count, 1, "only the header row is pending");
        assert!(
            block.encoded_bytes > HEADER_ROW_SIZE,
            "segment-tail bytes count toward the batch byte limit"
        );

        let wrong_hash = [0x42u8; 32];
        assert!(matches!(
            prepare(&writer, 0, wrong_hash, &body),
            Err(IndexError::BlockIdentityMismatch {
                height: 0,
                expected,
                actual,
            }) if expected == wrong_hash && actual == hash
        ));
        Ok(())
    }

    #[test]
    fn prepare_block_for_rejects_malformed_bodies() -> Result<(), TestError> {
        type Mangle = fn(Vec<u8>) -> Vec<u8>;
        type Check = fn(&IndexError) -> bool;
        let cases: [(&str, Mangle, Check); 3] = [
            (
                "short body",
                |body| body[..40].to_vec(),
                |error| {
                    matches!(
                        error,
                        IndexError::BlockParse(DecodeError::EndOfData {
                            needed: 40,
                            available: 40,
                        })
                    )
                },
            ),
            (
                "truncated transaction",
                |body| body[..body.len() - 8].to_vec(),
                |error| matches!(error, IndexError::BlockParse(DecodeError::EndOfData { .. })),
            ),
            (
                "trailing bytes",
                |mut body| {
                    body.push(0);
                    body
                },
                |error| {
                    matches!(
                        error,
                        IndexError::BlockParse(DecodeError::TrailingBytes { remaining: 1 })
                    )
                },
            ),
        ];

        for (label, mangle, check) in cases {
            let store = Arc::new(MemoryStore::default());
            let writer = IndexWriter::open(Arc::clone(&store), 1)?;
            let body = mangle(read_fixture(0)?);
            let hash = if label == "trailing bytes" {
                block_hash(&body)
            } else {
                [0_u8; 32]
            };

            let error = writer
                .prepare_block_for(IndexCapabilities::TX_LOOKUP, 0, hash, &body)
                .err()
                .ok_or(TestError::Missing("expected a parse rejection"))?;
            assert!(check(&error), "{label}: unexpected error {error:?}");
            for cf in [
                ColumnFamily::TxDir,
                ColumnFamily::ScriptPost,
                ColumnFamily::SpendDir,
                ColumnFamily::BlockHeaders,
            ] {
                assert_eq!(store.count(cf), 0, "{label}: {cf:?} must stay empty");
            }
        }
        Ok(())
    }

    #[test]
    fn commit_forward_and_rollback_are_atomic_and_ordered() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let body0 = read_fixture(0)?;
        let body1 = read_fixture(1)?;
        let txid0 = coinbase_txid(&body0)?;
        let txid1 = coinbase_txid(&body1)?;
        let block0 = prepare(&writer, 0, block_hash(&body0), &body0)?;
        let block1 = prepare(&writer, 1, block_hash(&body1), &body1)?;
        let block0_watermark = block0.watermark();
        let block1_watermark = block1.watermark();
        assert_eq!(block1.parent_hash, block0.hash);
        assert_eq!(block1.parent_hash, parent_hash(&body1));

        let mut batch = common::batch_with_limits(
            block0,
            PreparedBatchLimits {
                max_rows: 1_000,
                max_bytes: 1_000_000,
            },
        );
        assert!(batch.try_push(block1).is_ok());
        let watermark = writer.commit_forward(batch)?;
        assert_eq!(watermark, block1_watermark);
        assert_eq!(writer.watermark()?, Some(watermark));
        assert_eq!(
            store.count(bitcoin_rs_storage::ColumnFamily::BlockHeaders),
            2
        );

        let wrong_prev = IndexWatermark {
            height: 0,
            hash: [0x42; 32],
        };
        assert!(matches!(
            commit_rollback_one_for(
                &mut writer,
                IndexCapabilities::HISTORICAL,
                Some(wrong_prev),
                &body1
            ),
            Err(IndexError::WatermarkMismatch { .. })
        ));
        assert_eq!(writer.watermark()?, Some(block1_watermark));

        commit_rollback_one_for(
            &mut writer,
            IndexCapabilities::HISTORICAL,
            Some(block0_watermark),
            &body1,
        )?;
        assert_eq!(writer.watermark()?, Some(block0_watermark));
        assert_eq!(
            store.count(bitcoin_rs_storage::ColumnFamily::BlockHeaders),
            1
        );
        assert_eq!(tx_row_count(&store, &txid0)?, 1);
        assert_eq!(tx_row_count(&store, &txid1)?, 0);

        assert!(matches!(
            commit_rollback_one_for(
                &mut writer,
                IndexCapabilities::HISTORICAL,
                Some(block0_watermark),
                &body1
            ),
            Err(IndexError::BlockIdentityMismatch { .. })
        ));

        Ok(())
    }

    #[test]
    fn snapshot_scan_preserves_position_values() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let body = read_fixture(0)?;
        let block = deserialize::<Block>(&body)?;
        let txid = block.txs[0].txid();
        let prepared = prepare(&writer, 0, block_hash(&body), &body)?;
        let batch = common::single_block_batch(prepared);
        writer.commit_forward(batch)?;

        let snapshot = writer.snapshot()?;
        let scan = snapshot.transaction_rows(
            &txid,
            PrefixScanLimit {
                max_rows: 10,
                max_bytes: 1_024,
            },
        )?;

        assert!(scan.complete);
        assert_eq!(scan.rows.len(), 1);
        assert_eq!(scan.rows[0].row.height(), 0);
        assert_eq!(
            TxPositionValue::decode(&scan.rows[0].value).map(<[TxPosition]>::len),
            Some(1)
        );
        Ok(())
    }

    #[test]
    fn spending_rows_carry_transaction_positions() -> Result<(), TestError> {
        let mut block = Network::Regtest.genesis_block();
        let funding_txid = block.txs[0].txid();
        let spending_tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: funding_txid,
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: block.txs[0].outputs[0].value,
                script_pubkey: Script::new(),
            }],
        };
        block.txs.push(spending_tx.clone());
        let body = consensus_bytes(&block);
        let spending_bytes = consensus_bytes(&spending_tx);
        let position = TxPosition::new(
            u32::try_from(body.len() - spending_bytes.len())?,
            u32::try_from(spending_bytes.len())?,
        );

        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let prepared = prepare(&writer, 0, block_hash(&body), &body)?;
        let batch = common::single_block_batch(prepared);
        writer.commit_forward(batch)?;

        let snapshot = writer.snapshot()?;
        let outpoint = OutPoint {
            txid: funding_txid,
            vout: 0,
        };
        let scan = snapshot.spending_rows(
            &outpoint,
            PrefixScanLimit {
                max_rows: 10,
                max_bytes: 1_024,
            },
        )?;
        assert!(scan.complete);
        assert_eq!(scan.rows.len(), 1);
        let positions = TxPositionValue::decode(&scan.rows[0].value).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "spending position")
        })?;
        assert_eq!(positions, &[position]);
        let start = usize::try_from(position.offset())?;
        let end = usize::try_from(position.end().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "position end")
        })?)?;
        assert_eq!(deserialize::<Tx>(&body[start..end])?, spending_tx);
        Ok(())
    }

    #[test]
    fn capability_commits_own_only_their_rows_and_watermarks() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let body = read_fixture(0)?;
        let hash = block_hash(&body);
        let txid = coinbase_txid(&body)?;
        let scripthash = coinbase_scripthash(&body)?;
        let limits = PreparedBatchLimits {
            max_rows: 100,
            max_bytes: 1_000_000,
        };

        let tx_block = prepare_for(&writer, IndexCapabilities::TX_LOOKUP, 0, hash, &body)?;
        assert_eq!(tx_block.row_count, 1, "shared block identity");
        let mut tx_batch = PreparedBatch::new(limits);
        assert!(tx_batch.try_push(tx_block).is_ok());
        writer.commit_forward(tx_batch)?;

        let watermark = IndexWatermark { height: 0, hash };
        assert_eq!(
            writer.watermarks()?,
            bitcoin_rs_projection::IndexWatermarks {
                compact_filters: None,
                tx_lookup: Some(watermark),
                script_history: None,
                script_live: None,
            }
        );
        assert_eq!(tx_row_count(&store, &txid)?, 1);
        assert_eq!(
            funding_row_count(&store, scripthash)?,
            0,
            "no script history before its capability commits"
        );
        assert_eq!(store.count(ColumnFamily::SpendDir), 0);
        assert_eq!(store.count(ColumnFamily::BlockHeaders), 1);

        let script_index_block =
            prepare_for(&writer, IndexCapabilities::SCRIPT_HISTORY, 0, hash, &body)?;
        assert_eq!(script_index_block.row_count, 1, "shared block identity");
        let mut script_index_batch = PreparedBatch::new(limits);
        assert!(script_index_batch.try_push(script_index_block).is_ok());
        writer.commit_forward(script_index_batch)?;

        assert_eq!(
            writer.watermarks()?,
            bitcoin_rs_projection::IndexWatermarks {
                compact_filters: None,
                tx_lookup: Some(watermark),
                script_history: Some(watermark),
                script_live: None,
            }
        );
        assert_eq!(tx_row_count(&store, &txid)?, 1);
        assert!(
            funding_row_count(&store, scripthash)? > 0,
            "script history rows are published"
        );
        assert_eq!(store.count(ColumnFamily::SpendDir), 0);
        assert_eq!(store.count(ColumnFamily::BlockHeaders), 1);
        Ok(())
    }

    #[test]
    fn aligned_capabilities_share_one_atomic_commit() -> Result<(), TestError> {
        let store = Arc::new(CallTrackingStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let body = read_fixture(0)?;
        let hash = block_hash(&body);
        let block = prepare_for(&writer, IndexCapabilities::HISTORICAL, 0, hash, &body)?;
        let batch = common::single_block_batch(block);

        writer.commit_forward(batch)?;

        assert_eq!(store.durable_writes.load(Ordering::Relaxed), 1);
        let watermark = IndexWatermark { height: 0, hash };
        assert_eq!(
            writer.watermarks()?,
            bitcoin_rs_projection::IndexWatermarks {
                compact_filters: None,
                tx_lookup: Some(watermark),
                script_history: Some(watermark),
                script_live: None,
            }
        );
        Ok(())
    }

    // IDX-04
    #[test]
    fn script_index_reset_preserves_tx_lookup_and_shared_identity() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let body = read_fixture(0)?;
        let hash = block_hash(&body);
        let block = prepare_for(&writer, IndexCapabilities::HISTORICAL, 0, hash, &body)?;
        let batch = common::single_block_batch(block);
        writer.commit_forward(batch)?;

        writer.reset_capabilities(IndexCapabilities::SCRIPT_HISTORY)?;

        assert_eq!(
            writer.watermarks()?,
            bitcoin_rs_projection::IndexWatermarks {
                compact_filters: None,
                tx_lookup: Some(IndexWatermark { height: 0, hash }),
                script_history: None,
                script_live: None,
            }
        );
        assert_eq!(tx_row_count(&store, &coinbase_txid(&body)?)?, 1);
        assert_eq!(funding_row_count(&store, coinbase_scripthash(&body)?)?, 0);
        assert_eq!(store.count(ColumnFamily::SpendDir), 0);
        assert_eq!(store.count(ColumnFamily::BlockHeaders), 1);
        assert_eq!(stored_idle_version(&store)?, 1);
        Ok(())
    }

    // IDX-04
    #[test]
    fn tx_lookup_reset_preserves_script_history_directories() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let body = read_fixture(0)?;
        let hash = block_hash(&body);
        let script = coinbase_scripthash(&body)?;
        let block = prepare_for(&writer, IndexCapabilities::HISTORICAL, 0, hash, &body)?;
        writer.commit_forward(common::single_block_batch(block))?;

        let txid = coinbase_txid(&body)?;
        let shared_dir_rows = store.count(ColumnFamily::TxDir);
        assert!(
            shared_dir_rows > 0,
            "the fixture publishes transaction directory rows"
        );
        assert_eq!(tx_row_count(&store, &txid)?, 1);

        writer.reset_capabilities(IndexCapabilities::TX_LOOKUP)?;

        assert_eq!(
            writer.watermarks()?.script_history,
            Some(IndexWatermark { height: 0, hash })
        );
        assert_eq!(writer.watermarks()?.tx_lookup, None);
        assert_eq!(
            store.count(ColumnFamily::TxDir),
            shared_dir_rows,
            "the reset keeps the transaction directory ScriptHistory still publishes"
        );
        assert_eq!(
            tx_row_count(&store, &txid)?,
            0,
            "the reset TxLookup answers no transaction rows"
        );
        let snapshot = writer.snapshot()?;
        let funding = snapshot.funding_rows(script, SCAN_ALL)?.rows;
        assert_eq!(
            funding.len(),
            1,
            "the retained ScriptHistory rows still answer funding"
        );
        Ok(())
    }

    // IDX-07
    #[test]
    fn group_rollback_releases_identity_and_refuses_a_second_member() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let body0 = read_fixture(0)?;
        let body1 = read_fixture(1)?;
        let block0 = prepare_for(
            &writer,
            IndexCapabilities::HISTORICAL,
            0,
            block_hash(&body0),
            &body0,
        )?;
        let block1 = prepare_for(
            &writer,
            IndexCapabilities::HISTORICAL,
            1,
            block_hash(&body1),
            &body1,
        )?;
        let watermark0 = block0.watermark();
        let mut batch = common::batch_with_limits(
            block0,
            PreparedBatchLimits {
                max_rows: 100,
                max_bytes: 1_000_000,
            },
        );
        assert!(batch.try_push(block1).is_ok());
        writer.commit_forward(batch)?;

        commit_rollback_one_for(
            &mut writer,
            IndexCapabilities::TX_LOOKUP,
            Some(watermark0),
            &body1,
        )?;
        commit_rollback_one_for(&mut writer, IndexCapabilities::TX_LOOKUP, None, &body0)?;
        assert_eq!(
            store.count(ColumnFamily::BlockHeaders),
            0,
            "the tail group releases both identities"
        );
        assert!(
            matches!(
                commit_rollback_one_for(
                    &mut writer,
                    IndexCapabilities::SCRIPT_HISTORY,
                    Some(watermark0),
                    &body1,
                ),
                Err(IndexError::NonContiguousPrepared { watermark: None })
            ),
            "the group already moved ScriptHistory, so a second ScriptHistory rollback is refused"
        );
        Ok(())
    }

    #[test]
    fn resetting_the_only_cursor_removes_shared_identity() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let body = read_fixture(0)?;
        let block = prepare_for(
            &writer,
            IndexCapabilities::TX_LOOKUP,
            0,
            block_hash(&body),
            &body,
        )?;
        let batch = common::single_block_batch(block);
        writer.commit_forward(batch)?;

        writer.reset_capabilities(IndexCapabilities::TX_LOOKUP)?;

        assert_eq!(store.count(ColumnFamily::TxDir), 0);
        assert_eq!(store.count(ColumnFamily::BlockHeaders), 0);
        Ok(())
    }

    // IDX-04, IDX-05
    #[test]
    fn open_resumes_interrupted_capability_reset() -> Result<(), TestError> {
        for reset_tx_lookup in [false, true] {
            let store = Arc::new(MemoryStore::default());
            let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
            let body = read_fixture(0)?;
            let hash = block_hash(&body);
            let block = prepare_for(&writer, IndexCapabilities::HISTORICAL, 0, hash, &body)?;
            let prepared = common::single_block_batch(block);
            writer.commit_forward(prepared)?;
            assert!(
                !tail_log_keys(&store)?.is_empty(),
                "the committed block supplies recovery history before interruption"
            );
            drop(writer);

            let mask = if reset_tx_lookup {
                SCRIPT_HISTORY_MASK | TX_LOOKUP_MASK
            } else {
                SCRIPT_HISTORY_MASK
            };
            let mut interrupted = store.new_batch();
            interrupted.put(ColumnFamily::UtxoMeta, RESET_KEY, &claim_bytes(mask, 3, 0));
            interrupted.delete(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY);
            if reset_tx_lookup {
                interrupted.delete(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY);
            }
            interrupted.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
            store.write_durable(interrupted)?;

            let writer = IndexWriter::open(Arc::clone(&store), 1)?;

            assert_eq!(writer.watermarks()?.tx_lookup.is_none(), reset_tx_lookup);
            assert!(writer.watermarks()?.script_history.is_none());
            assert_eq!(
                tx_row_count(&store, &coinbase_txid(&body)?)?,
                usize::from(!reset_tx_lookup)
            );
            assert_eq!(funding_row_count(&store, coinbase_scripthash(&body)?)?, 0);
            assert_eq!(store.count(ColumnFamily::SpendDir), 0);
            assert_eq!(stored_idle_version(&store)?, 1);
            if reset_tx_lookup {
                assert!(
                    tail_log_keys(&store)?.is_empty(),
                    "resuming the last published tail-owner reset removes abandoned recovery history"
                );
            }
        }
        Ok(())
    }

    // IDX-05
    #[test]
    fn reset_claim_carries_mask_epoch_and_base_version() -> Result<(), TestError> {
        let store = Arc::new(CallTrackingStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 7)?;
        let body = read_fixture(0)?;
        let hash = block_hash(&body);
        let block = prepare_for(&writer, IndexCapabilities::HISTORICAL, 0, hash, &body)?;
        let prepared = common::single_block_batch(block);
        writer.commit_forward(prepared)?;
        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_consumer_cursor(fence, b"before-reset")?;

        let tail_logs_before = tail_log_keys(&store)?;
        assert!(
            !tail_logs_before.is_empty(),
            "the committed block anchored shared tail undo logs"
        );

        writer.reset_capabilities(IndexCapabilities::SCRIPT_HISTORY)?;

        let marker_puts: Vec<BatchLog> = store
            .logged_batches()
            .into_iter()
            .filter(|entry| entry.marker_put.is_some())
            .collect();
        assert_eq!(
            marker_puts.len(),
            2,
            "the reset writes its claim and its completion; the same-generation \
         resume must not add a redundant adoption rewrite"
        );
        assert!(marker_puts[0].durable, "the claim lands in a durable batch");
        assert_eq!(
            marker_puts[0].marker_put.as_deref(),
            Some(claim_bytes(0b10, 7, 0).as_slice()),
            "claim value is mask(1) || process_epoch(8 LE) || base_version(8 LE)"
        );
        assert_eq!(
            tail_log_keys(&store)?,
            tail_logs_before,
            "a ScriptHistory reset leaves the shared tail undo logs for the \
         surviving tail-bound capabilities"
        );
        assert_eq!(
            marker_puts[1].marker_put.as_deref(),
            Some(idle_bytes(1).as_slice()),
            "completion CASes the exact claim to Idle(base_version + 1)"
        );
        assert_eq!(
            marker_puts[1].deletes, 0,
            "completion never deletes the state key"
        );
        assert!(writer.consumer_cursor()?.is_none());
        Ok(())
    }

    #[test]
    fn ordinary_commits_are_excluded_by_a_reset_claim() -> Result<(), TestError> {
        #[derive(Clone, Copy)]
        enum Mutator {
            Forward,
            Rollback,
            Cursor,
        }
        let cases = [
            (Mutator::Forward, SCRIPT_HISTORY_MASK, SCRIPT_WATERMARK_KEY),
            (Mutator::Rollback, SCRIPT_HISTORY_MASK, SCRIPT_WATERMARK_KEY),
            (Mutator::Cursor, TX_LOOKUP_MASK, TX_WATERMARK_KEY),
        ];

        for (mutator, mask, dropped_watermark) in cases {
            let store = Arc::new(MemoryStore::default());
            seed_populated_store(&store, 1)?;
            let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
            let rollback_body = read_fixture(0)?;
            let forward_body = read_fixture(1)?;

            let mut prepared = PreparedBatch::new(PreparedBatchLimits {
                max_rows: 100,
                max_bytes: 1_000_000,
            });
            if matches!(mutator, Mutator::Forward) {
                let block = prepare_for(
                    &writer,
                    IndexCapabilities::TX_LOOKUP,
                    1,
                    block_hash(&forward_body),
                    &forward_body,
                )?;
                assert!(prepared.try_push(block).is_ok());
            }
            let rows_before = store.rows(ColumnFamily::TxDir);
            let (fence, _) = writer.fenced_watermarks()?;
            if matches!(mutator, Mutator::Cursor) {
                writer.commit_consumer_cursor(fence, b"old-cursor")?;
            }

            let mut claim = store.new_batch();
            claim.put(ColumnFamily::UtxoMeta, RESET_KEY, &claim_bytes(mask, 9, 0));
            claim.delete(ColumnFamily::UtxoMeta, dropped_watermark);
            claim.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
            store.write_durable(claim)?;

            let result = match mutator {
                Mutator::Forward => writer
                    .commit_forward_with_cursor(
                        fence,
                        prepared,
                        ConsumerCursorUpdate::Set(b"stale-forward"),
                    )
                    .map(drop),
                Mutator::Rollback => writer.commit_rollback_one_for_with_cursor(
                    fence,
                    IndexCapabilities::TX_LOOKUP,
                    None,
                    &rollback_body,
                    ConsumerCursorUpdate::Set(b"stale-rollback"),
                ),
                Mutator::Cursor => writer.commit_consumer_cursor(fence, b"stale-cursor"),
            };

            assert!(matches!(result, Err(IndexError::ResetInProgress)));
            assert!(store.get(ColumnFamily::UtxoMeta, RESET_KEY)?.is_some());
            if mask != TX_LOOKUP_MASK {
                assert_eq!(store.rows(ColumnFamily::TxDir), rows_before);
                assert_eq!(
                    writer.watermarks()?.tx_lookup.map(|mark| mark.height),
                    Some(0)
                );
            }
            assert!(writer.consumer_cursor()?.is_none());
            assert_eq!(stored_idle_version(&store)?, 1);
        }
        Ok(())
    }

    #[test]
    fn obsolete_and_malformed_reset_claims_are_rejected_without_writes() -> Result<(), TestError> {
        let mut old_claim = vec![SCRIPT_HISTORY_MASK];
        old_claim.extend_from_slice(&9_u64.to_le_bytes());
        for marker in [
            vec![SCRIPT_HISTORY_MASK],
            old_claim,
            vec![0; 17],
            vec![0xff],
        ] {
            let store = Arc::new(CallTrackingStore::default());
            seed_populated_store(&store, 1)?;
            let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
            store.put(ColumnFamily::UtxoMeta, RESET_KEY, &marker)?;
            let before = dump_all(&store.inner);
            let baseline = store.logged_batches().len();
            assert!(matches!(
                IndexWriter::open(Arc::clone(&store), 7),
                Err(IndexError::InvalidResetMarker)
            ));
            assert!(matches!(
                writer.fenced_watermarks(),
                Err(IndexError::InvalidResetMarker)
            ));
            assert!(matches!(
                writer.reset_capabilities(IndexCapabilities::SCRIPT_HISTORY),
                Err(IndexError::InvalidResetMarker)
            ));
            assert_eq!(dump_all(&store.inner), before);
            assert_eq!(store.logged_batches().len(), baseline);
        }
        Ok(())
    }

    fn seed_populated_stores() -> Result<(Arc<MemoryStore>, Arc<MemoryStore>), TestError> {
        let control = Arc::new(MemoryStore::default());
        let interrupted = Arc::new(MemoryStore::default());
        for store in [&control, &interrupted] {
            seed_populated_store(store, 1)?;
        }
        Ok((control, interrupted))
    }

    fn seed_populated_store(store: &Arc<impl KvStore>, generation: u64) -> Result<(), TestError> {
        let mut writer = IndexWriter::open(Arc::clone(store), generation)?;
        let body = read_fixture(0)?;
        let block = prepare_for(
            &writer,
            IndexCapabilities::HISTORICAL,
            0,
            block_hash(&body),
            &body,
        )?;
        let prepared = common::single_block_batch(block);
        writer.commit_forward(prepared)?;
        Ok(())
    }

    fn crash_after_marker_commit(store: &MemoryStore) -> Result<(), TestError> {
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::UtxoMeta, RESET_KEY, &claim_bytes(0b10, 3, 0));
        batch.delete(ColumnFamily::UtxoMeta, &[0x00, b'S']);
        batch.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
        store.write_durable(batch)?;
        Ok(())
    }

    fn dump_all(store: &MemoryStore) -> Vec<(ColumnFamily, Vec<u8>, Vec<u8>)> {
        let mut rows = Vec::new();
        for &cf in ColumnFamily::ALL {
            rows.extend(
                store
                    .rows(cf)
                    .into_iter()
                    .map(|(key, value)| (cf, key, value)),
            );
        }
        rows
    }

    #[test]
    fn interrupted_reset_resumes_from_every_crash_point() -> Result<(), TestError> {
        type CrashPoint = fn(&MemoryStore) -> Result<(), TestError>;
        let cases: [(&str, CrashPoint); 3] = [
            ("after the marker commit", |_store| Ok(())),
            ("mid-delete", |store| {
                let mut partial = store.new_batch();
                for (key, _) in store.rows(ColumnFamily::ScriptPost).into_iter().take(2) {
                    partial.delete(ColumnFamily::ScriptPost, &key);
                }
                store.write_durable(partial)?;
                Ok(())
            }),
            (
                "after the deletion loops, before the marker clear",
                |store| {
                    for cf in [
                        ColumnFamily::ScriptPost,
                        ColumnFamily::ScriptDict,
                        ColumnFamily::SpendDir,
                        ColumnFamily::ScriptStats,
                    ] {
                        let mut batch = store.new_batch();
                        for (key, _) in store.rows(cf) {
                            batch.delete(cf, &key);
                        }
                        store.write_durable(batch)?;
                    }
                    Ok(())
                },
            ),
        ];

        for (label, crash) in cases {
            let (control, interrupted) = seed_populated_stores()?;
            crash_after_marker_commit(&interrupted)?;
            crash(&interrupted)?;

            let control_writer = IndexWriter::open(Arc::clone(&control), 1)?;
            control_writer.reset_capabilities(IndexCapabilities::SCRIPT_HISTORY)?;
            drop(control_writer);
            IndexWriter::open(Arc::clone(&interrupted), 4)?;

            assert_eq!(
                dump_all(&control),
                dump_all(&interrupted),
                "resume {label} converges byte-identically"
            );
        }
        Ok(())
    }

    const TX_LOOKUP_MASK: u8 = 0b01;

    const SCRIPT_HISTORY_MASK: u8 = 0b10;

    const TX_WATERMARK_KEY: &[u8] = &[0x00, b'T'];

    const SCRIPT_WATERMARK_KEY: &[u8] = &[0x00, b'S'];

    const CURSOR_KEY: &[u8] = &[0x00, b'C'];

    const FORMAT_KEY: &[u8] = &[0x00, b'V'];

    #[derive(Clone, Copy, Debug)]
    struct CompetingClaim {
        generation: u64,
        requested_mask: u8,
    }

    #[derive(Default)]
    struct ForeignFenceStore {
        inner: MemoryStore,
        on_claim: Mutex<Option<CompetingClaim>>,
        on_delete: Mutex<Option<CompetingClaim>>,
        on_clear: Mutex<Option<CompetingClaim>>,
        unconditional_delete_after_claim_change: AtomicBool,
    }

    fn racing_store(
        hook: fn(&mut ForeignFenceStore) -> &mut Mutex<Option<CompetingClaim>>,
    ) -> Arc<ForeignFenceStore> {
        let mut store = ForeignFenceStore::default();
        *hook(&mut store) = Mutex::new(Some(CompetingClaim {
            generation: 9,
            requested_mask: SCRIPT_HISTORY_MASK,
        }));
        Arc::new(store)
    }

    fn crash_mid_fence(
        store: &ForeignFenceStore,
        mask: u8,
        epoch: u64,
    ) -> Result<(), StorageError> {
        let mut crashed = store.inner.new_batch();
        crashed.put(
            ColumnFamily::UtxoMeta,
            RESET_KEY,
            &claim_bytes(mask, epoch, 0),
        );
        crashed.delete(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY);
        crashed.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
        store.inner.write_durable(crashed)
    }

    impl ForeignFenceStore {
        fn count(&self, cf: ColumnFamily) -> usize {
            self.inner.count(cf)
        }

        fn run_competing_claim(&self, claim: CompetingClaim) -> Result<bool, StorageError> {
            let observed = self.inner.get(ColumnFamily::UtxoMeta, RESET_KEY)?;
            let (current_mask, base_version) = match observed.as_deref() {
                None => (0, 0),
                Some(bytes) if is_idle_marker(bytes) => (
                    0,
                    decode_u64_le(bytes, 1).ok_or_else(|| {
                        StorageError::IncompatibleData("idle marker truncated".into())
                    })?,
                ),
                Some(bytes) => {
                    let base = decode_u64_le(bytes, 9).ok_or_else(|| {
                        StorageError::IncompatibleData("claim marker truncated".into())
                    })?;
                    (bytes[0], base)
                }
            };
            let mask = current_mask | claim.requested_mask;
            let published_claim = claim_bytes(mask, claim.generation, base_version);
            let condition = match observed.as_deref() {
                Some(expected) => WriteCondition::Equals {
                    cf: ColumnFamily::UtxoMeta,
                    key: RESET_KEY,
                    expected,
                },
                None => WriteCondition::Absent {
                    cf: ColumnFamily::UtxoMeta,
                    key: RESET_KEY,
                },
            };
            let mut batch = self.inner.new_batch();
            batch.put(ColumnFamily::UtxoMeta, RESET_KEY, &published_claim);
            batch.put(
                ColumnFamily::UtxoMeta,
                FORMAT_KEY,
                &bitcoin_rs_projection::INDEX_FORMAT_VERSION_VALUE,
            );
            if mask & TX_LOOKUP_MASK != 0 {
                batch.delete(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY);
            }
            if mask & SCRIPT_HISTORY_MASK != 0 {
                batch.delete(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY);
            }
            batch.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
            self.inner
                .write_durable_if(std::slice::from_ref(&condition), batch)
        }

        fn take_injection(&self, ops: &[BatchOp]) -> Option<CompetingClaim> {
            if let Some(value) = put_value_of(ops, ColumnFamily::UtxoMeta, RESET_KEY) {
                return if is_idle_marker(&value) {
                    self.on_clear.lock().take()
                } else {
                    self.on_claim.lock().take()
                };
            }
            if deletes_derived_rows(ops) {
                return self.on_delete.lock().take();
            }
            None
        }
    }

    impl KvStore for ForeignFenceStore {
        fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get(cf, key)
        }

        fn iter_prefix<'a>(
            &'a self,
            cf: ColumnFamily,
            prefix: &[u8],
        ) -> Result<KvIter<'a>, StorageError> {
            self.inner.iter_prefix(cf, prefix)
        }

        fn scan_prefix_from_bounded(
            &self,
            cf: ColumnFamily,
            prefix: &[u8],
            start: &[u8],
            limit: PrefixScanLimit,
        ) -> Result<PrefixScan, StorageError> {
            self.inner
                .scan_prefix_from_bounded(cf, prefix, start, limit)
        }

        fn new_batch(&self) -> BufferedWriteBatch {
            self.inner.new_batch()
        }

        fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
            let ops = batch.into_ops();
            if let Some(claim) = self.take_injection(&ops) {
                self.run_competing_claim(claim)?;
                self.unconditional_delete_after_claim_change
                    .store(true, Ordering::Release);
            }
            self.inner.write(restore_batch(ops))
        }

        fn write_durable_if(
            &self,
            conditions: &[WriteCondition<'_>],
            batch: BufferedWriteBatch,
        ) -> Result<bool, StorageError> {
            let ops = batch.into_ops();
            if let Some(claim) = self.take_injection(&ops) {
                self.run_competing_claim(claim)?;
            }
            self.inner.write_durable_if(conditions, restore_batch(ops))
        }

        fn flush(&self) -> Result<(), StorageError> {
            self.inner.flush()
        }

        fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
            self.inner.snapshot()
        }

        fn arm_persist_fault(&self, _fault: bitcoin_rs_storage::PersistFault) {}

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

        fn delete_range(
            &self,
            cf: ColumnFamily,
            start: &[u8],
            end: &[u8],
        ) -> Result<(), StorageError> {
            self.inner.delete_range(cf, start, end)
        }

        fn checkpoint(&self, dir: &std::path::Path) -> Result<(), StorageError> {
            self.inner.checkpoint(dir)
        }

        fn engine_cache_bytes(&self) -> u64 {
            self.inner.engine_cache_bytes()
        }
    }

    #[test]
    fn clear_loss_restarts_and_completes_the_merged_fence() -> Result<(), TestError> {
        let store = racing_store(|s| &mut s.on_clear);
        seed_populated_store(&store, 1)?;
        crash_mid_fence(&store, TX_LOOKUP_MASK, 3)?;

        let writer = IndexWriter::open(Arc::clone(&store), 4)?;

        assert_eq!(stored_idle_version(&store)?, 1);
        assert_eq!(store.count(ColumnFamily::TxDir), 0);
        assert_eq!(store.count(ColumnFamily::ScriptPost), 0);
        assert_eq!(store.count(ColumnFamily::SpendDir), 0);
        assert_eq!(store.count(ColumnFamily::BlockHeaders), 0);
        assert_eq!(writer.watermarks()?.tx_lookup, None);
        assert_eq!(writer.watermarks()?.script_history, None);
        Ok(())
    }

    #[test]
    fn changed_claim_prevents_stale_row_deletion() -> Result<(), TestError> {
        let store = racing_store(|s| &mut s.on_delete);
        seed_populated_store(&store, 1)?;
        crash_mid_fence(&store, TX_LOOKUP_MASK, 4)?;

        IndexWriter::open(Arc::clone(&store), 4)?;

        assert!(
            !store
                .unconditional_delete_after_claim_change
                .load(Ordering::Acquire),
            "a stale reset operation deleted rows after the exact claim changed"
        );
        assert_eq!(stored_idle_version(&store)?, 1);
        for cf in [
            ColumnFamily::TxDir,
            ColumnFamily::ScriptPost,
            ColumnFamily::SpendDir,
            ColumnFamily::BlockHeaders,
        ] {
            assert_eq!(store.count(cf), 0, "{cf:?} reset did not complete");
        }
        Ok(())
    }

    #[test]
    fn competing_claim_during_claim_merges_different_masks() -> Result<(), TestError> {
        let store = racing_store(|s| &mut s.on_claim);
        seed_populated_store(&store, 1)?;

        let writer = IndexWriter::open(Arc::clone(&store), 4)?;
        writer.reset_capabilities(IndexCapabilities::TX_LOOKUP)?;

        assert!(
            stored_idle_version(&store)? == 1,
            "the retried union claim owns and completes its fence"
        );
        assert!(
            store
                .get(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY)?
                .is_none()
        );
        assert!(
            store
                .get(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY)?
                .is_none()
        );
        assert_eq!(store.count(ColumnFamily::TxDir), 0);
        assert_eq!(
            store.count(ColumnFamily::ScriptPost),
            0,
            "the raced-in capability joins the union and is cleared too"
        );
        assert_eq!(store.count(ColumnFamily::SpendDir), 0);
        assert_eq!(store.count(ColumnFamily::BlockHeaders), 0);
        Ok(())
    }

    #[test]
    fn reset_index_adopts_a_foreign_fence_as_an_all_capability_reset() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        seed_populated_store(&store, 1)?;
        let mut foreign = store.new_batch();
        foreign.put(
            ColumnFamily::UtxoMeta,
            RESET_KEY,
            &claim_bytes(SCRIPT_HISTORY_MASK, 9, 0),
        );
        foreign.delete(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY);
        foreign.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
        store.write_durable(foreign)?;

        IndexWriter::reset_index(store.as_ref(), 4)?;

        let writer = IndexWriter::open(Arc::clone(&store), 4)?;
        assert_eq!(stored_idle_version(&store)?, 1);
        assert_eq!(writer.watermarks()?.tx_lookup, None);
        assert_eq!(writer.watermarks()?.script_history, None);
        assert!(writer.consumer_cursor()?.is_none());
        for cf in [
            ColumnFamily::TxDir,
            ColumnFamily::ScriptPost,
            ColumnFamily::SpendDir,
            ColumnFamily::BlockHeaders,
        ] {
            assert_eq!(store.count(cf), 0, "{cf:?} survived the full reset");
        }
        Ok(())
    }

    #[test]
    fn format_stays_current_after_reset_and_rebuild() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        seed_populated_store(&store, 1)?;

        let writer = IndexWriter::open(Arc::clone(&store), 1)?;
        writer.reset_capabilities(IndexCapabilities::HISTORICAL)?;
        drop(writer);

        seed_populated_store(&store, 1)?;

        assert_eq!(
            store.get(ColumnFamily::UtxoMeta, &[0x00, b'V'])?.as_deref(),
            Some(bitcoin_rs_projection::INDEX_FORMAT_VERSION_VALUE.as_slice()),
            "the row-format gate survives reset and rebuild"
        );
        let txid = coinbase_txid(&read_fixture(0)?)?;
        let indexer = Indexer::new(Arc::clone(&store));
        let snapshot = indexer.snapshot()?;
        let rows = snapshot.transaction_rows(&txid, ROW_LIMIT)?;
        assert_eq!(
            rows.rows
                .first()
                .and_then(|row| TxPositionValue::decode(&row.value))
                .map(<[TxPosition]>::len),
            Some(1),
            "rebuilt rows carry transaction byte positions"
        );
        Ok(())
    }

    #[test]
    fn batch_caps_admit_oversized_first_block() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        let writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let body0 = read_fixture(0)?;
        let body1 = read_fixture(1)?;

        let block0 = prepare(&writer, 0, block_hash(&body0), &body0)?;
        let block1 = prepare(&writer, 1, block_hash(&body1), &body1)?;
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: 1,
            max_bytes: usize::MAX,
        });
        assert!(batch.try_push(block0).is_ok());
        assert!(batch.try_push(block1).is_err());
        assert_eq!(batch.len(), 1);
        assert_eq!(batch.row_count(), 1);
        assert!(batch.is_full());
        assert_eq!(
            batch.watermark(),
            Some(IndexWatermark {
                height: 0,
                hash: block_hash(&body0),
            })
        );

        let block0 = prepare(&writer, 0, block_hash(&body0), &body0)?;
        let block1 = prepare(&writer, 1, block_hash(&body1), &body1)?;
        let mut batch = common::batch_with_limits(
            block0,
            PreparedBatchLimits {
                max_rows: 0,
                max_bytes: 0,
            },
        );
        assert!(batch.try_push(block1).is_err());
        assert_eq!(batch.len(), 1);
        assert!(
            batch.encoded_bytes() > HEADER_ROW_SIZE,
            "segment-tail bytes count toward the batch"
        );
        assert!(batch.is_full());
        assert_eq!(
            batch.watermark(),
            Some(IndexWatermark {
                height: 0,
                hash: block_hash(&body0),
            })
        );

        Ok(())
    }

    #[test]
    fn commit_forward_accepts_terminal_height() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        let current = IndexWatermark {
            height: u32::MAX - 1,
            hash: [0; 32],
        };
        store.put(
            bitcoin_rs_storage::ColumnFamily::UtxoMeta,
            &[0x00, b'V'],
            &bitcoin_rs_projection::INDEX_FORMAT_VERSION_VALUE,
        )?;
        store.put(
            bitcoin_rs_storage::ColumnFamily::UtxoMeta,
            &[0x00, b'T'],
            &current.to_bytes(),
        )?;

        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let body = read_fixture(0)?;
        let expected_hash = block_hash(&body);
        let block = prepare_for(
            &writer,
            IndexCapabilities::TX_LOOKUP,
            u32::MAX,
            expected_hash,
            &body,
        )?;
        let batch = common::single_block_batch(block);

        let watermark = writer.commit_forward(batch)?;
        assert_eq!(
            watermark,
            IndexWatermark {
                height: u32::MAX,
                hash: expected_hash,
            }
        );
        Ok(())
    }

    #[test]
    fn commit_forward_rejects_height_overflow() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        let overflow = IndexWatermark {
            height: u32::MAX,
            hash: [0xab; 32],
        };
        store.put(
            bitcoin_rs_storage::ColumnFamily::UtxoMeta,
            &[0x00, b'V'],
            &bitcoin_rs_projection::INDEX_FORMAT_VERSION_VALUE,
        )?;
        store.put(
            bitcoin_rs_storage::ColumnFamily::UtxoMeta,
            &[0x00, b'T'],
            &overflow.to_bytes(),
        )?;

        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let body = read_fixture(0)?;
        let block = prepare_for(
            &writer,
            IndexCapabilities::TX_LOOKUP,
            0,
            block_hash(&body),
            &body,
        )?;
        let batch = common::single_block_batch(block);
        assert!(matches!(
            writer.commit_forward(batch),
            Err(IndexError::NonContiguousPrepared { watermark })
                if watermark == Some(overflow)
        ));
        Ok(())
    }

    #[test]
    fn rollback_rejects_prev_at_genesis() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let body = read_fixture(0)?;
        let block = prepare(&writer, 0, block_hash(&body), &body)?;
        let batch = common::single_block_batch(block);
        writer.commit_forward(batch)?;

        assert!(matches!(
            commit_rollback_one_for(
                &mut writer,
                IndexCapabilities::HISTORICAL,
                Some(IndexWatermark {
                    height: 0,
                    hash: [0u8; 32]
                }),
                &body
            ),
            Err(IndexError::NonContiguousPrepared { .. })
        ));
        Ok(())
    }

    #[test]
    fn rocksdb_snapshot_preserves_position_values() -> Result<(), TestError> {
        let temp = tempfile::TempDir::new()?;
        let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open(temp.path())?);
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let body = read_fixture(0)?;
        let block = deserialize::<Block>(&body)?;
        let txid = block.txs[0].txid();
        let scripthash = ScriptHash::new(&block.txs[0].outputs[0].script_pubkey);
        let prepared = prepare(&writer, 0, block_hash(&body), &body)?;
        let batch = common::single_block_batch(prepared);
        writer.commit_forward(batch)?;

        let snapshot = writer.snapshot()?;
        let limit = PrefixScanLimit {
            max_rows: 10,
            max_bytes: 1_024,
        };
        let transaction_rows = snapshot.transaction_rows(&txid, limit)?;
        let funding_rows = snapshot.funding_rows(scripthash, limit)?;

        assert_eq!(transaction_rows.rows.len(), 1);
        assert_eq!(funding_rows.rows.len(), 1);
        let positions = TxPositionValue::decode(&transaction_rows.rows[0].value)
            .ok_or("transaction rows carry positions")?;
        assert_eq!(positions.len(), 1);
        let occurrences = bitcoin_rs_projection::types::ScriptHistoryOccurrence::decode_all(
            &funding_rows.rows[0].value,
        )
        .ok_or("funding rows carry occurrences")?;
        assert_eq!(occurrences.len(), 1, "one transaction occurrence per row");
        assert_eq!(occurrences[0].scripthash, scripthash);
        assert_eq!(occurrences[0].txid, *txid.as_bytes());
        assert_eq!(occurrences[0].position, positions[0]);
        assert_eq!(
            occurrences[0].flags,
            bitcoin_rs_projection::types::ScriptHistoryOccurrence::FUNDING
        );
        Ok(())
    }

    fn inject_full_claim(store: &MemoryStore, process_epoch: u64) -> Result<(), TestError> {
        let mut claim = store.new_batch();
        claim.put(
            ColumnFamily::UtxoMeta,
            RESET_KEY,
            &claim_bytes(TX_LOOKUP_MASK | SCRIPT_HISTORY_MASK, process_epoch, 0),
        );
        claim.put(
            ColumnFamily::UtxoMeta,
            FORMAT_KEY,
            &bitcoin_rs_projection::INDEX_FORMAT_VERSION_VALUE,
        );
        claim.delete(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY);
        claim.delete(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY);
        claim.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
        store.write_durable(claim)?;
        Ok(())
    }

    #[test]
    fn full_reset_between_derive_and_commit_rejects_stale_work() -> Result<(), TestError> {
        let cases = [
            ("forward", false, ConsumerCursorUpdate::Keep),
            ("rollback", true, ConsumerCursorUpdate::Keep),
            (
                "forward with cursor",
                false,
                ConsumerCursorUpdate::Set(b"stale-cursor"),
            ),
        ];

        for (label, rollback, cursor_update) in cases {
            let store = Arc::new(MemoryStore::default());
            seed_populated_store(&store, 1)?;
            let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
            let (fence, _) = writer.fenced_watermarks()?;

            let result = if rollback {
                let body = read_fixture(0)?;
                inject_full_claim(&store, 9)?;
                writer.commit_rollback_one_for_with_cursor(
                    fence,
                    IndexCapabilities::TX_LOOKUP,
                    None,
                    &body,
                    cursor_update,
                )
            } else {
                let body = read_fixture(1)?;
                let block = prepare_for(
                    &writer,
                    IndexCapabilities::TX_LOOKUP,
                    1,
                    block_hash(&body),
                    &body,
                )?;
                let prepared = common::single_block_batch(block);
                inject_full_claim(&store, 9)?;
                writer
                    .commit_forward_with_cursor(fence, prepared, cursor_update)
                    .map(drop)
            };

            assert!(
                matches!(result, Err(IndexError::ResetInProgress)),
                "{label}"
            );
            assert_eq!(writer.watermarks()?, IndexWatermarks::default(), "{label}");
            assert!(
                writer.consumer_cursor()?.is_none(),
                "{label}: stale cursor bytes are never published past a reset"
            );
            assert_eq!(stored_idle_version(&store)?, 1, "{label}");
        }
        Ok(())
    }

    #[test]
    fn double_reset_same_generation_still_rejects_stale_commit() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        seed_populated_store(&store, 1)?;
        let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
        writer.reset_capabilities(IndexCapabilities::HISTORICAL)?;
        let (stale_fence, _) = writer.fenced_watermarks()?;
        writer.reset_capabilities(IndexCapabilities::HISTORICAL)?;
        assert_eq!(stored_idle_version(&store)?, 2);

        let body = read_fixture(0)?;
        let block = prepare_for(
            &writer,
            IndexCapabilities::TX_LOOKUP,
            0,
            block_hash(&body),
            &body,
        )?;
        let prepared = common::single_block_batch(block);
        let result =
            writer.commit_forward_with_cursor(stale_fence, prepared, ConsumerCursorUpdate::Keep);
        assert!(matches!(result, Err(IndexError::ResetInProgress)));
        assert_eq!(writer.watermarks()?, IndexWatermarks::default());

        let body = read_fixture(0)?;
        let block = prepare_for(
            &writer,
            IndexCapabilities::TX_LOOKUP,
            0,
            block_hash(&body),
            &body,
        )?;
        let prepared = common::single_block_batch(block);
        let (fresh_fence, _) = writer.fenced_watermarks()?;
        writer.commit_forward_with_cursor(fresh_fence, prepared, ConsumerCursorUpdate::Keep)?;
        assert_eq!(writer.watermark()?.map(|mark| mark.height), Some(0));
        assert_eq!(stored_idle_version(&store)?, 2);
        Ok(())
    }

    // EVT-03
    #[test]
    fn intermediate_rollback_deletes_cursor_and_survives_reopen() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
        let (fence, _) = writer.fenced_watermarks()?;
        let body0 = read_fixture(0)?;
        let block = prepare_for(
            &writer,
            IndexCapabilities::HISTORICAL,
            0,
            block_hash(&body0),
            &body0,
        )?;
        let mut prepared = PreparedBatch::new(PreparedBatchLimits {
            max_rows: 100,
            max_bytes: 1_000_000,
        });
        assert!(prepared.try_push(block).is_ok());
        writer.commit_forward_with_cursor(
            fence,
            prepared,
            ConsumerCursorUpdate::Set(b"cursor-at-0"),
        )?;
        assert_eq!(
            writer.consumer_cursor()?.as_deref(),
            Some(b"cursor-at-0".as_slice())
        );

        commit_rollback_one_for(&mut writer, IndexCapabilities::HISTORICAL, None, &body0)?;
        assert!(writer.consumer_cursor()?.is_none());

        drop(writer);
        let reopened = IndexWriter::open(Arc::clone(&store), 4)?;
        assert!(reopened.consumer_cursor()?.is_none(), "cursor stays gone");
        assert!(reopened.watermark()?.is_none());
        assert!(store.get(ColumnFamily::UtxoMeta, RESET_KEY)?.is_none());
        Ok(())
    }

    #[test]
    fn intermediate_rollback_removes_stale_cursor() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        seed_populated_store(&store, 1)?;
        let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_consumer_cursor(fence, b"cursor-at-0")?;

        let body0 = read_fixture(0)?;
        commit_rollback_one_for(&mut writer, IndexCapabilities::TX_LOOKUP, None, &body0)?;
        assert!(writer.consumer_cursor()?.is_none());

        let block = prepare_for(
            &writer,
            IndexCapabilities::TX_LOOKUP,
            0,
            block_hash(&body0),
            &body0,
        )?;
        let mut prepared = PreparedBatch::new(PreparedBatchLimits {
            max_rows: 100,
            max_bytes: 1_000_000,
        });
        assert!(prepared.try_push(block).is_ok());
        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_forward_with_cursor(fence, prepared, ConsumerCursorUpdate::Keep)?;
        assert_eq!(writer.watermark()?.map(|mark| mark.height), Some(0));
        assert!(
            writer.consumer_cursor()?.is_none(),
            "Keep preserves the rollback's deletion"
        );
        Ok(())
    }
    #[test]
    fn stale_cursor_publish_is_rejected_when_watermarks_lag() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        seed_populated_store(&store, 1)?;
        let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
        let (stale_fence, _) = writer.fenced_watermarks()?;

        let body1 = read_fixture(1)?;
        let block = prepare_for(
            &writer,
            IndexCapabilities::TX_LOOKUP,
            1,
            block_hash(&body1),
            &body1,
        )?;
        let prepared = common::single_block_batch(block);
        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_forward_with_cursor(fence, prepared, ConsumerCursorUpdate::Keep)?;

        let result = writer.commit_consumer_cursor(stale_fence, b"lagging");
        assert!(
            matches!(result, Err(IndexError::StaleIndexState)),
            "a lagging watermark must reject the cursor publish: {result:?}"
        );
        assert!(writer.consumer_cursor()?.is_none());

        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_consumer_cursor(fence, b"current")?;
        assert_eq!(
            writer.consumer_cursor()?.as_deref(),
            Some(b"current".as_slice())
        );
        Ok(())
    }

    #[test]
    fn cursor_publish_rejects_a_watermark_race() -> Result<(), TestError> {
        struct Case {
            label: &'static str,
            drop_tx_watermark: bool,
            script_family: bool,
            raced_hash: [u8; 32],
        }
        let cases = [
            Case {
                label: "tx watermark race",
                drop_tx_watermark: false,
                script_family: false,
                raced_hash: [0x42; 32],
            },
            Case {
                label: "absent tx watermark race",
                drop_tx_watermark: true,
                script_family: false,
                raced_hash: [0x42; 32],
            },
            Case {
                label: "script watermark race",
                drop_tx_watermark: false,
                script_family: true,
                raced_hash: [0x99; 32],
            },
        ];

        for case in cases {
            let store = Arc::new(CallTrackingStore::default());
            seed_populated_store(&store, 1)?;
            if case.drop_tx_watermark {
                let mut del = store.new_batch();
                del.delete(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY);
                store.write_durable(del)?;
            }

            let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
            let (fence, _) = writer.fenced_watermarks()?;
            let raced = IndexWatermark {
                height: 1,
                hash: case.raced_hash,
            };
            if case.script_family {
                *store.cursor_race_script_watermark.lock() = Some(raced);
            } else {
                *store.cursor_race_tx_watermark.lock() = Some(raced);
            }

            let result = writer.commit_consumer_cursor(fence, b"stale");
            assert!(
                matches!(result, Err(IndexError::StaleIndexState)),
                "{}: must reject the cursor publish: {result:?}",
                case.label
            );
            assert!(writer.consumer_cursor()?.is_none(), "{}", case.label);
            let observed = if case.script_family {
                writer.watermarks()?.script_history
            } else {
                writer.watermarks()?.tx_lookup
            };
            assert_eq!(observed, Some(raced), "{}", case.label);
        }
        Ok(())
    }

    #[test]
    fn oversized_first_row_does_not_escape_reset() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        seed_populated_store(&store, 1)?;
        let oversized: Vec<u8> = vec![0xAB; 300 * 1024];
        store.put(ColumnFamily::TxDir, &[0x00, 0x00], &oversized)?;

        IndexWriter::reset_index(store.as_ref(), 4)?;

        assert_eq!(store.count(ColumnFamily::TxDir), 0);
        assert_eq!(store.count(ColumnFamily::ScriptPost), 0);
        assert_eq!(store.count(ColumnFamily::SpendDir), 0);
        assert_eq!(store.count(ColumnFamily::BlockHeaders), 0);
        assert_eq!(stored_idle_version(&store)?, 1);
        Ok(())
    }

    fn populated_idle_tracking_store() -> Result<Arc<CallTrackingStore>, TestError> {
        let store = Arc::new(CallTrackingStore::default());
        seed_populated_store(&store, 1)?;

        let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
        writer.reset_capabilities(IndexCapabilities::HISTORICAL)?;
        let body = read_fixture(0)?;
        let block = prepare_for(
            &writer,
            IndexCapabilities::HISTORICAL,
            0,
            block_hash(&body),
            &body,
        )?;
        let prepared = common::single_block_batch(block);
        writer.commit_forward(prepared)?;
        assert_eq!(stored_idle_version(&store)?, 1);

        Ok(store)
    }

    fn stored_state_revision(store: &CallTrackingStore) -> Result<Option<u64>, TestError> {
        match store
            .inner
            .get(ColumnFamily::UtxoMeta, ORDINARY_STATE_REVISION_KEY)?
        {
            None => Ok(None),
            Some(bytes) => {
                let raw: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
                    std::io::Error::other(format!(
                        "ordinary-state revision is not one little-endian u64: {bytes:?}"
                    ))
                })?;
                Ok(Some(u64::from_le_bytes(raw)))
            }
        }
    }

    fn assert_state_revision(
        store: &CallTrackingStore,
        expected: Option<u64>,
    ) -> Result<(), TestError> {
        let raw = store
            .inner
            .get(ColumnFamily::UtxoMeta, ORDINARY_STATE_REVISION_KEY)?;
        let encoded = match (&expected, raw.as_deref()) {
            (None, None) => true,
            (Some(value), Some(bytes)) => bytes == value.to_le_bytes(),
            _ => false,
        };
        assert!(
            encoded,
            "ordinary-state revision {raw:?} does not encode {expected:?}"
        );
        Ok(())
    }

    fn arm_reset_after_malformed_watermark_read(
        store: &CallTrackingStore,
    ) -> Result<(), StorageError> {
        let mut batch = store.inner.new_batch();
        batch.put(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY, b"malformed");
        store.inner.write(batch)?;
        *store.snapshot_reset_after_tx_watermark_read.lock() = Some((2, 4));
        Ok(())
    }

    #[test]
    fn rollback_commit_rejects_reset_during_header_read() -> Result<(), TestError> {
        let store = populated_idle_tracking_store()?;
        let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
        let (fence, _) = writer.fenced_watermarks()?;
        let body = read_fixture(0)?;

        *store.fence_reset_during_header_read.lock() = Some((2, 4));
        let result = writer.commit_rollback_one_for_with_cursor(
            fence,
            IndexCapabilities::TX_LOOKUP,
            None,
            &body,
            ConsumerCursorUpdate::Clear,
        );

        assert!(
            matches!(result, Err(IndexError::ResetInProgress)),
            "rollback commit misclassified a reset during header validation: {result:?}"
        );
        assert_eq!(stored_idle_version(&store)?, 2);
        assert_eq!(writer.watermarks()?, IndexWatermarks::default());
        Ok(())
    }

    #[test]
    fn fenced_watermarks_prefers_reset_over_watermark_decode_error() -> Result<(), TestError> {
        let store = populated_idle_tracking_store()?;
        let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
        arm_reset_after_malformed_watermark_read(&store)?;

        let result = writer.fenced_watermarks();

        assert!(
            matches!(result, Err(IndexError::ResetInProgress)),
            "fenced watermark read exposed stale corruption after reset: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn fenced_watermarks_captures_every_capability_in_one_coherent_snapshot()
    -> Result<(), TestError> {
        let store = populated_idle_tracking_store()?;
        let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
        store.read_order.lock().clear();
        store.snapshot_read_order.lock().clear();
        let snapshots_before = store.snapshots.load(Ordering::Relaxed);

        let (_fence, watermarks) = writer.fenced_watermarks()?;

        assert!(watermarks.tx_lookup.is_some());
        assert!(watermarks.script_history.is_some());
        assert!(watermarks.script_live.is_none());
        assert_eq!(
            store.snapshots.load(Ordering::Relaxed),
            snapshots_before + 1,
            "one successful fence capture must use one storage snapshot"
        );

        *store.snapshot_reset_after_tx_watermark_read.lock() = Some((2, 4));
        let result = writer.fenced_watermarks();
        assert!(
            matches!(result, Err(IndexError::ResetInProgress)),
            "a capture spanning a concurrent reset discards derived state: {result:?}"
        );

        assert_eq!(stored_idle_version(&store)?, 2);
        let (fence, watermarks) = writer.fenced_watermarks()?;
        assert_eq!(watermarks, IndexWatermarks::default());
        let body = read_fixture(0)?;
        let block = prepare_for(
            &writer,
            IndexCapabilities::HISTORICAL,
            0,
            block_hash(&body),
            &body,
        )?;
        let prepared = common::single_block_batch(block);
        writer.commit_forward_with_cursor(fence, prepared, ConsumerCursorUpdate::Keep)?;
        assert_eq!(writer.watermark()?.map(|mark| mark.height), Some(0));
        Ok(())
    }

    #[test]
    fn unchanged_reset_surfaces_malformed_watermark_decode() -> Result<(), TestError> {
        let store = populated_idle_tracking_store()?;
        let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
        let mut batch = store.inner.new_batch();
        batch.put(ColumnFamily::UtxoMeta, TX_WATERMARK_KEY, b"malformed");
        store.inner.write(batch)?;

        let result = writer.fenced_watermarks();

        assert!(
            matches!(result, Err(IndexError::InvalidWatermark)),
            "with the reset unchanged, the corruption itself surfaces: {result:?}"
        );
        assert_eq!(stored_idle_version(&store)?, 1);
        assert_state_revision(&store, Some(3))?;
        Ok(())
    }

    #[test]
    fn reset_change_takes_precedence_over_stale_reset_parse_error() -> Result<(), TestError> {
        let store = populated_idle_tracking_store()?;
        let writer = IndexWriter::open(Arc::clone(&store), 4)?;
        let mut malformed = store.inner.new_batch();
        malformed.put(ColumnFamily::UtxoMeta, RESET_KEY, b"malformed");
        store.inner.write(malformed)?;
        *store.snapshot_reset_after_revision_read.lock() = Some((2, 4));

        let result = writer.reset_capabilities(IndexCapabilities::TX_LOOKUP);

        assert!(
            matches!(result, Err(IndexError::ResetInProgress)),
            "a moved reset must supersede the stale parse error: {result:?}"
        );
        assert_eq!(stored_idle_version(&store)?, 2);
        assert_state_revision(&store, Some(4))?;
        Ok(())
    }

    #[test]
    fn cursor_only_contention_rejects_stale_revision() -> Result<(), TestError> {
        let store = Arc::new(CallTrackingStore::default());
        seed_populated_store(&store, 1)?;
        let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_consumer_cursor(fence, b"first")?;
        assert_state_revision(&store, Some(2))?;

        let result = writer.commit_consumer_cursor(fence, b"second");
        assert!(
            matches!(result, Err(IndexError::StaleIndexState)),
            "cursor-only contention must reject as stale state: {result:?}"
        );
        assert_eq!(
            writer.consumer_cursor()?.as_deref(),
            Some(b"first".as_slice())
        );
        assert_state_revision(&store, Some(2))?;

        let (fresh_fence, _) = writer.fenced_watermarks()?;
        writer.commit_consumer_cursor(fresh_fence, b"third")?;
        assert_eq!(
            writer.consumer_cursor()?.as_deref(),
            Some(b"third".as_slice())
        );
        assert_state_revision(&store, Some(3))?;
        Ok(())
    }

    #[test]
    fn each_ordinary_mutator_advances_the_revision_exactly_once() -> Result<(), TestError> {
        let store = Arc::new(CallTrackingStore::default());
        assert_state_revision(&store, None)?;
        let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;

        let body0 = read_fixture(0)?;
        let block = prepare_for(
            &writer,
            IndexCapabilities::HISTORICAL,
            0,
            block_hash(&body0),
            &body0,
        )?;
        let prepared = common::single_block_batch(block);
        writer.commit_forward(prepared)?;
        assert_state_revision(&store, Some(1))?;

        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_consumer_cursor(fence, b"cursor-1")?;
        assert_state_revision(&store, Some(2))?;

        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_rollback_one_for_with_cursor(
            fence,
            IndexCapabilities::TX_LOOKUP,
            None,
            &body0,
            ConsumerCursorUpdate::Clear,
        )?;
        assert_state_revision(&store, Some(3))?;

        let block = prepare_for(
            &writer,
            IndexCapabilities::TX_LOOKUP,
            0,
            block_hash(&body0),
            &body0,
        )?;
        let prepared = common::single_block_batch(block);
        writer.commit_forward(prepared)?;
        assert_state_revision(&store, Some(4))?;

        commit_rollback_one_for(&mut writer, IndexCapabilities::TX_LOOKUP, None, &body0)?;
        assert_state_revision(&store, Some(5))?;
        assert_eq!(
            stored_state_revision(&store)?,
            Some(5),
            "decode helper agrees with the raw-byte assert"
        );
        Ok(())
    }

    #[test]
    fn ordinary_revision_overflow_rejects_forward_without_destroying_state() -> Result<(), TestError>
    {
        let store = Arc::new(MemoryStore::default());
        seed_populated_store(&store, 1)?;
        let mut near_ceiling = store.new_batch();
        near_ceiling.put(
            ColumnFamily::UtxoMeta,
            ORDINARY_STATE_REVISION_KEY,
            &(u64::MAX - 1).to_le_bytes(),
        );
        store.write_durable(near_ceiling)?;

        let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_consumer_cursor(fence, b"at-ceiling")?;
        assert_eq!(
            store.get(ColumnFamily::UtxoMeta, ORDINARY_STATE_REVISION_KEY)?,
            Some(u64::MAX.to_le_bytes().to_vec())
        );

        let body = read_fixture(1)?;
        let block = prepare_for(
            &writer,
            IndexCapabilities::TX_LOOKUP,
            1,
            block_hash(&body),
            &body,
        )?;
        let prepared = common::single_block_batch(block);
        let (fence, _) = writer.fenced_watermarks()?;
        let before = dump_all(store.as_ref());

        let result = writer.commit_forward_with_cursor(fence, prepared, ConsumerCursorUpdate::Keep);
        assert!(
            matches!(result, Err(IndexError::StateRevisionOverflow)),
            "a full revision must refuse the next ordinary mutation: {result:?}"
        );
        assert_eq!(
            dump_all(store.as_ref()),
            before,
            "revision overflow must not mutate any row or metadata"
        );
        Ok(())
    }

    #[test]
    fn reset_counter_overflow_is_rejected_before_any_write() -> Result<(), TestError> {
        for version_overflow in [true, false] {
            let store = Arc::new(MemoryStore::default());
            seed_populated_store(&store, 1)?;
            let mut state = store.new_batch();
            if version_overflow {
                state.put(ColumnFamily::UtxoMeta, RESET_KEY, &idle_bytes(u64::MAX - 1));
            } else {
                state.put(ColumnFamily::UtxoMeta, RESET_KEY, &idle_bytes(1));
                state.put(
                    ColumnFamily::UtxoMeta,
                    ORDINARY_STATE_REVISION_KEY,
                    &u64::MAX.to_le_bytes(),
                );
            }
            store.write_durable(state)?;

            let writer = IndexWriter::open(Arc::clone(&store), 4)?;
            if version_overflow {
                writer.reset_capabilities(IndexCapabilities::TX_LOOKUP)?;
                assert_eq!(
                    store.get(ColumnFamily::UtxoMeta, RESET_KEY)?,
                    Some(idle_bytes(u64::MAX))
                );
            }
            let before = dump_all(store.as_ref());

            let selected = if version_overflow {
                IndexCapabilities::SCRIPT_HISTORY
            } else {
                IndexCapabilities::TX_LOOKUP
            };
            let result = writer.reset_capabilities(selected);
            if version_overflow {
                assert!(
                    matches!(result, Err(IndexError::ResetVersionOverflow)),
                    "an idle version at u64::MAX must refuse the next reset: {result:?}"
                );
            } else {
                assert!(
                    matches!(result, Err(IndexError::StateRevisionOverflow)),
                    "a full revision must refuse the reset before any claim: {result:?}"
                );
            }
            assert_eq!(
                dump_all(store.as_ref()),
                before,
                "overflow must precede claim publication, deletion, and every other write"
            );
        }
        Ok(())
    }
    // IDX-05
    #[test]
    fn same_mask_claim_is_adopted_cooperatively_without_rewrite() -> Result<(), TestError> {
        let store = Arc::new(CallTrackingStore::default());
        seed_populated_store(&store, 1)?;
        let body = read_fixture(0)?;
        let mut crash = store.new_batch();
        crash.put(
            ColumnFamily::UtxoMeta,
            RESET_KEY,
            &claim_bytes(SCRIPT_HISTORY_MASK, 9, 0),
        );
        crash.delete(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY);
        crash.delete(ColumnFamily::UtxoMeta, CURSOR_KEY);
        store.write_durable(crash)?;

        let baseline = store.logged_batches().len();
        let writer = IndexWriter::open(Arc::clone(&store), 7)?;

        let markers: Vec<BatchLog> = store.logged_batches()[baseline..]
            .iter()
            .filter(|entry| entry.marker_put.is_some())
            .cloned()
            .collect();
        assert_eq!(markers.len(), 1, "no adoption rewrite: {markers:?}");
        assert!(markers[0].durable, "the completion is durable");
        assert_eq!(
            markers[0].marker_put.as_deref(),
            Some(idle_bytes(1).as_slice())
        );
        assert_eq!(
            store.get(ColumnFamily::UtxoMeta, RESET_KEY)?,
            Some(idle_bytes(1))
        );
        assert_state_revision(&store, Some(2))?;

        assert!(writer.watermarks()?.tx_lookup.is_some());
        assert!(writer.watermarks()?.script_history.is_none());
        assert_eq!(tx_row_count(&store, &coinbase_txid(&body)?)?, 1);
        assert_eq!(funding_row_count(&store, coinbase_scripthash(&body)?)?, 0);
        assert_eq!(store.count(ColumnFamily::SpendDir), 0);
        assert!(writer.consumer_cursor()?.is_none());
        Ok(())
    }

    #[test]
    fn union_growth_preserves_claim_identity_and_deletes_full_union_state() -> Result<(), TestError>
    {
        let store = Arc::new(CallTrackingStore::default());
        seed_populated_store(&store, 1)?;
        let mut writer = IndexWriter::open(Arc::clone(&store), 7)?;
        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_consumer_cursor(fence, b"pending")?;

        let mut crash = store.new_batch();
        crash.put(
            ColumnFamily::UtxoMeta,
            RESET_KEY,
            &claim_bytes(SCRIPT_HISTORY_MASK, 9, 3),
        );
        crash.delete(ColumnFamily::UtxoMeta, SCRIPT_WATERMARK_KEY);
        store.write_durable(crash)?;

        let baseline = store.logged_batches().len();
        writer.reset_capabilities(IndexCapabilities::TX_LOOKUP)?;

        let markers: Vec<BatchLog> = store.logged_batches()[baseline..]
            .iter()
            .filter(|entry| entry.marker_put.is_some())
            .cloned()
            .collect();
        assert_eq!(
            markers.len(),
            2,
            "one grown claim, one completion: {markers:?}"
        );
        assert!(markers[0].durable, "the grown claim is durable");
        assert_eq!(
            markers[0].marker_put.as_deref(),
            Some(claim_bytes(TX_LOOKUP_MASK | SCRIPT_HISTORY_MASK, 9, 3).as_slice()),
            "growth changes byte zero only; width, process epoch, and base survive raw"
        );
        assert_eq!(
            markers[1].marker_put.as_deref(),
            Some(idle_bytes(4).as_slice())
        );
        assert_eq!(markers[1].deletes, 0, "completion never deletes");

        assert_eq!(
            store.get(ColumnFamily::UtxoMeta, RESET_KEY)?,
            Some(idle_bytes(4))
        );
        assert_state_revision(&store, Some(3))?;
        assert!(writer.watermarks()?.tx_lookup.is_none());
        assert!(writer.watermarks()?.script_history.is_none());
        assert!(writer.consumer_cursor()?.is_none());
        for cf in [
            ColumnFamily::TxDir,
            ColumnFamily::ScriptPost,
            ColumnFamily::SpendDir,
            ColumnFamily::BlockHeaders,
        ] {
            assert_eq!(store.count(cf), 0, "{cf:?} joined the union reset");
        }
        Ok(())
    }

    #[test]
    fn second_writer_contention_rejects_a_stale_fence() -> Result<(), TestError> {
        for rollback in [false, true] {
            let store = Arc::new(MemoryStore::default());
            seed_populated_store(&store, 1)?;
            let mut winner = IndexWriter::open(Arc::clone(&store), 4)?;
            let mut loser = IndexWriter::open(Arc::clone(&store), 5)?;
            let (winner_fence, _) = winner.fenced_watermarks()?;
            let (loser_fence, _) = loser.fenced_watermarks()?;
            let mut rows_after_winner = Vec::new();

            let postings_before_winner = store.count(ColumnFamily::ScriptPost);
            let result = if rollback {
                let body = read_fixture(0)?;
                winner.commit_rollback_one_for_with_cursor(
                    winner_fence,
                    IndexCapabilities::TX_LOOKUP,
                    None,
                    &body,
                    ConsumerCursorUpdate::Clear,
                )?;
                loser.commit_rollback_one_for_with_cursor(
                    loser_fence,
                    IndexCapabilities::TX_LOOKUP,
                    None,
                    &body,
                    ConsumerCursorUpdate::Clear,
                )
            } else {
                let body = read_fixture(1)?;
                let replay =
                    |writer: &mut IndexWriter<MemoryStore>| -> Result<PreparedBatch, IndexError> {
                        let block = prepare_for(
                            writer,
                            IndexCapabilities::TX_LOOKUP,
                            1,
                            block_hash(&body),
                            &body,
                        )?;
                        let prepared = common::single_block_batch(block);
                        Ok(prepared)
                    };
                let prepared = replay(&mut winner)?;
                let watermark = winner.commit_forward_with_cursor(
                    winner_fence,
                    prepared,
                    ConsumerCursorUpdate::Set(b"winner"),
                )?;
                assert_eq!(watermark.height, 1);
                rows_after_winner = store.rows(ColumnFamily::TxDir);
                let prepared = replay(&mut loser)?;
                loser
                    .commit_forward_with_cursor(
                        loser_fence,
                        prepared,
                        ConsumerCursorUpdate::Set(b"loser"),
                    )
                    .map(drop)
            };
            assert!(
                matches!(result, Err(IndexError::StaleIndexState)),
                "the loser must lose the conditional write: {result:?}"
            );

            let expected_script_history = if rollback { None } else { Some(0) };
            assert_eq!(
                winner.watermarks()?.script_history.map(|mark| mark.height),
                expected_script_history,
                "a TxLookup rollback moves the shared-tail group, ScriptHistory included"
            );
            assert_eq!(
                store.get(ColumnFamily::UtxoMeta, ORDINARY_STATE_REVISION_KEY)?,
                Some(2_u64.to_le_bytes().to_vec())
            );

            if rollback {
                assert!(winner.watermarks()?.tx_lookup.is_none());
                assert_eq!(store.count(ColumnFamily::TxDir), 0);
                assert_eq!(store.count(ColumnFamily::SpendDir), 0);
                assert_eq!(
                    store.count(ColumnFamily::BlockHeaders),
                    0,
                    "the tail group releases its identity"
                );
                assert!(winner.consumer_cursor()?.is_none());
            } else {
                assert_eq!(winner.watermark()?.map(|mark| mark.height), Some(1));
                assert_eq!(
                    store.count(ColumnFamily::TxDir),
                    4,
                    "seed and winner tx rows"
                );
                assert_eq!(
                    store.count(ColumnFamily::ScriptPost),
                    postings_before_winner,
                    "a TxLookup-only commit writes no postings"
                );
                assert_eq!(store.rows(ColumnFamily::TxDir), rows_after_winner);
                assert_eq!(
                    winner.consumer_cursor()?.as_deref(),
                    Some(b"winner".as_slice())
                );
            }
        }
        Ok(())
    }

    #[test]
    fn consumer_cursor_must_be_the_reserved_width() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        seed_populated_store(&store, 1)?;
        let mut writer = IndexWriter::open(Arc::clone(&store), 4)?;
        let (fence, _) = writer.fenced_watermarks()?;
        assert!(writer.consumer_cursor()?.is_none());

        let oversized = vec![0_u8; CURSOR_BYTE_LEN + 1];
        let result = writer.commit_consumer_cursor(fence, &oversized);
        assert!(
            matches!(&result, Err(IndexError::CursorLength { len }) if *len == CURSOR_BYTE_LEN + 1),
            "a cursor wider than CURSOR_BYTE_LEN must be refused: {result:?}"
        );
        assert!(
            writer.consumer_cursor()?.is_none(),
            "a refused cursor writes nothing"
        );

        let reserved = vec![0_u8; CURSOR_BYTE_LEN];
        writer.commit_consumer_cursor(fence, &reserved)?;
        assert_eq!(
            writer.consumer_cursor()?.as_deref(),
            Some(reserved.as_slice())
        );
        Ok(())
    }
}
mod live_handoff {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use arc_swap::{ArcSwap, ArcSwapOption};
    use bitcoin::blockdata::block::Header as BtcHeader;
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::script::Builder;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, CompactTarget, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
    };
    use bitcoin_rs_consensus::latch::LatchWriter;
    use bitcoin_rs_consensus::primitives::layout::ParsedBlock;
    use bitcoin_rs_consensus::primitives::{BlockHash, Hash256, Txid};
    use bitcoin_rs_execution::chain::{
        BlockTree, BlockTreeReader, NodeStatus, TipReader, TipSnapshot,
    };
    use bitcoin_rs_projection::IndexCapabilities;
    use bitcoin_rs_projection::portable::IndexBundleDirective;
    use bitcoin_rs_projection::query_api::DerivedIndexQuery;
    use bitcoin_rs_projection::reconcile::{ChainCursorSource, ConsumerCursor};
    use bitcoin_rs_projection::runtime::{
        DEFAULT_BATCH_LIMITS, DerivedIndexLifecycle, DerivedIndexOpenSpec,
        DerivedIndexQueryAdapter, DerivedIndexRuntime, DerivedIndexWorker, Generation,
        IndexAheadError, IndexAheadSink, open_derived_index_store_on_worker,
    };
    use bitcoin_rs_storage::block_body::{BlockBodyReadError, BlockBodySource, BlockBodyStore};
    use bitcoin_rs_storage::pruning::{HistoryAccess, RetentionBudget, RetentionRegistry};
    use bitcoin_rs_storage::{
        CommittedBlock, CommittedFacts, CreatedOutput, FactsScript, RocksDbStore, SpentPrevout,
        StorageBackend, StorageError, TxFacts,
    };
    use parking_lot::RwLock;

    type BodyMap = HashMap<(u32, [u8; 32]), Vec<u8>>;

    struct CountingBlockBodyStore {
        bodies: Arc<RwLock<BodyMap>>,
        load_count: Arc<AtomicU64>,
    }

    impl BlockBodyStore for CountingBlockBodyStore {
        fn persist_block_body(
            &self,
            _height: u32,
            _hash: Hash256,
            _body: &[u8],
        ) -> Result<(), StorageError> {
            Ok(())
        }

        fn load_block_body(
            &self,
            height: u32,
            hash: Hash256,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            self.load_count.fetch_add(1, Ordering::SeqCst);
            let guard = self.bodies.read();
            Ok(guard.get(&(height, hash.to_le_bytes())).cloned())
        }

        fn undo_record(
            &self,
            _height: u32,
            _hash: Hash256,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(None)
        }

        fn sync(&self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    struct PassthroughBodySource {
        bodies: Arc<RwLock<BodyMap>>,
        calls: Arc<AtomicU64>,
    }

    impl BlockBodySource for PassthroughBodySource {
        fn block_body(
            &self,
            height: u32,
            hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, BlockBodyReadError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let guard = self.bodies.read();
            Ok(guard
                .get(&(height, Hash256::from(hash).to_le_bytes()))
                .cloned())
        }

        fn block_body_range(
            &self,
            height: u32,
            hash: BlockHash,
            offset: u32,
            len: u32,
        ) -> Option<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let guard = self.bodies.read();
            let body = guard.get(&(height, Hash256::from(hash).to_le_bytes()))?;
            let start = usize::try_from(offset).ok()?;
            let end = start.checked_add(usize::try_from(len).ok()?)?;
            body.get(start..end).map(<[u8]>::to_vec)
        }
    }

    #[derive(Default)]
    struct TestProbe;

    impl ChainCursorSource for TestProbe {
        fn cursor(&self) -> ConsumerCursor {
            ConsumerCursor {
                epoch: 0,
                sequence: 0,
                height: 0,
                hash: Hash256::from_le_bytes(&[0_u8; 32]),
            }
        }
    }

    struct TestIndexAhead;

    impl IndexAheadSink for TestIndexAhead {
        fn report_index_ahead(
            &self,
            _capability: &str,
            _index_height: u32,
            _tip_height: u32,
            _tip_hash_be: &str,
            _index_hash_be: &str,
            _depth: u32,
            _unix_secs: u64,
        ) -> Result<(), IndexAheadError> {
            Ok(())
        }
    }

    fn make_coinbase(height: u32) -> Transaction {
        Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: Builder::new().push_int(i64::from(height)).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    fn make_tx(prev_txid: [u8; 32], prev_vout: u32, value: u64) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array(prev_txid),
                    vout: prev_vout,
                },
                script_sig: Builder::new().push_int(1).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::from_bytes(vec![0x52]),
            }],
        }
    }

    fn mine_test_block(prev: [u8; 32], height: u32, txs: Vec<Transaction>) -> bitcoin::Block {
        let mut txdata = Vec::with_capacity(txs.len() + 1);
        txdata.push(make_coinbase(height));
        txdata.extend(txs);
        let mut block = bitcoin::Block {
            header: BtcHeader {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: bitcoin::BlockHash::from_byte_array(prev),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_700_000_000 + height,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata,
        };
        block.header.merkle_root = block
            .compute_merkle_root()
            .unwrap_or_else(TxMerkleNode::all_zeros);
        while block.header.validate_pow(block.header.target()).is_err() {
            block.header.nonce = block.header.nonce.wrapping_add(1);
        }
        block
    }

    #[expect(
        clippy::expect_used,
        reason = "fixture decodes local regtest bytes with checked shapes"
    )]
    fn block_to_facts(
        block: &bitcoin::Block,
        height: u32,
        commit_id: u64,
        undo_scripts: &HashMap<([u8; 32], u32), (u64, FactsScript)>,
    ) -> CommittedFacts {
        let bytes = serialize(block);
        let parsed = ParsedBlock::parse_exact(&bytes).expect("valid block layout");
        let header_bytes = serialize(&block.header);
        let header: [u8; 80] = header_bytes[..80].try_into().expect("80 bytes header");
        let hash = block.block_hash().to_byte_array();
        let parent_hash = block.header.prev_blockhash.to_byte_array();

        let mut ptxs = parsed.transactions().iter();
        let mut txs = Vec::new();
        for (idx, tx) in block.txdata.iter().enumerate() {
            let ptx = ptxs.next().expect("ptx exists");
            let txid = tx.compute_txid().to_byte_array();
            let offset = ptx.span().start();
            let len = ptx.span().len();

            let mut inputs = Vec::new();
            if idx > 0 {
                for input in &tx.input {
                    let prev_txid = input.previous_output.txid.to_byte_array();
                    let prev_vout = input.previous_output.vout;
                    let (value, script) = undo_scripts
                        .get(&(prev_txid, prev_vout))
                        .cloned()
                        .unwrap_or((0, FactsScript::copy_from_slice(&[0x51])));
                    inputs.push(SpentPrevout {
                        txid: prev_txid,
                        vout: prev_vout,
                        value,
                        script,
                        height: 0,
                        coinbase: false,
                    });
                }
            }

            let mut outputs = Vec::new();
            for (vout, out) in tx.output.iter().enumerate() {
                let vout_u32 = u32::try_from(vout).expect("vout fits u32");
                outputs.push(CreatedOutput {
                    vout: vout_u32,
                    value: out.value.to_sat(),
                    script: FactsScript::copy_from_slice(out.script_pubkey.as_bytes()),
                });
            }

            txs.push(TxFacts {
                txid,
                offset,
                len,
                inputs,
                outputs,
            });
        }

        CommittedFacts {
            commit_id,
            blocks: vec![CommittedBlock {
                height,
                hash,
                parent_hash,
                header,
                txs,
            }],
        }
    }

    // PRJ-01
    #[test]
    #[expect(
        clippy::expect_used,
        reason = "the harness asserts wiring invariants on local fixtures"
    )]
    fn live_index_path_reads_zero_block_bodies() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let data_dir = temp_dir.path();
        let load_counter = Arc::new(AtomicU64::new(0));
        let source_calls = Arc::new(AtomicU64::new(0));
        let mut tree = BlockTree::new();
        let bodies = Arc::new(RwLock::new(BodyMap::new()));

        let genesis = mine_test_block([0_u8; 32], 0, Vec::new());
        let gen_bytes = serialize(&genesis);
        let gen_hash = genesis.block_hash().to_byte_array();
        let gen_header: bitcoin_rs_consensus::primitives::Header =
            bitcoin_rs_consensus::primitives::deserialize(&serialize(&genesis.header))
                .expect("header");
        let gen_id = tree
            .insert_header(gen_header, NodeStatus::HeaderValid)
            .expect("insert genesis");
        tree.record_applied_tx_count(gen_id, 1).expect("tx count");
        bodies.write().insert((0, gen_hash), gen_bytes);

        let b1_tx = make_tx(
            genesis.txdata[0].compute_txid().to_byte_array(),
            0,
            49_000_000,
        );
        let b1 = mine_test_block(gen_hash, 1, vec![b1_tx]);
        let b1_bytes = serialize(&b1);
        let b1_hash = b1.block_hash().to_byte_array();
        let b1_header: bitcoin_rs_consensus::primitives::Header =
            bitcoin_rs_consensus::primitives::deserialize(&serialize(&b1.header)).expect("header");
        let b1_id = tree
            .insert_header(b1_header, NodeStatus::HeaderValid)
            .expect("insert b1");
        tree.record_applied_tx_count(b1_id, 2).expect("tx count");
        bodies.write().insert((1, b1_hash), b1_bytes);

        let b2 = mine_test_block(b1_hash, 2, Vec::new());
        let b2_bytes = serialize(&b2);
        let b2_hash = b2.block_hash().to_byte_array();
        let b2_header: bitcoin_rs_consensus::primitives::Header =
            bitcoin_rs_consensus::primitives::deserialize(&serialize(&b2.header)).expect("header");
        let b2_id = tree
            .insert_header(b2_header, NodeStatus::HeaderValid)
            .expect("insert b2");
        tree.record_applied_tx_count(b2_id, 3).expect("tx count");
        bodies.write().insert((2, b2_hash), b2_bytes);

        let tip_node = tree.node(b2_id).expect("tip node");
        let tip = Arc::new(TipSnapshot {
            tip_id: b2_id,
            height: tip_node.height,
            chainwork: tip_node.chainwork,
            hash: tip_node.hash,
            chain_tx_count: tip_node.chain_tx_count,
        });
        let tip_reader = TipReader::new(Arc::new(ArcSwapOption::new(Some(tip))));
        let tree_reader = BlockTreeReader::new(Arc::new(RwLock::new(tree)));

        let body_store: Arc<dyn BlockBodyStore> = Arc::new(CountingBlockBodyStore {
            bodies: Arc::clone(&bodies),
            load_count: Arc::clone(&load_counter),
        });
        let body_source: Arc<dyn BlockBodySource> = Arc::new(PassthroughBodySource {
            bodies: Arc::clone(&bodies),
            calls: Arc::clone(&source_calls),
        });

        let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
        let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx.clone()));
        let lifecycle = Arc::new(ArcSwap::from_pointee(DerivedIndexLifecycle::Opening));
        let adapter = DerivedIndexQueryAdapter::new(Arc::clone(&lifecycle));
        let shutdown = Arc::new(LatchWriter::new());

        let (facts_tx, facts_rx) = crossbeam_channel::bounded(16);
        let facts_charge = bitcoin_rs_storage::budget::ChargeHandle::new(
            Arc::new(bitcoin_rs_storage::budget::UnboundedBudget),
            bitcoin_rs_storage::budget::BudgetOwner::FactsQueue,
        );
        let facts_gap = Arc::new(AtomicBool::new(false));

        let spec = DerivedIndexOpenSpec {
            scripthash_limit: bitcoin_rs_projection::runtime::DEFAULT_SCRIPTHASH_LIMIT,
            data_dir: data_dir.to_path_buf(),
            namespace: "txindex",
            storage_backend: StorageBackend::RocksDb,
            epoch: 1,
            enabled: IndexCapabilities::TX_LOOKUP,
            rollback_rebuild_cutover: u32::MAX,
            canonical_data_root: data_dir.to_path_buf(),
            open_store: Arc::new(move |dir| {
                let inner = RocksDbStore::open_with_cache(dir, 16 * 1024 * 1024)
                    .map_err(bitcoin_rs_projection::runtime::DerivedIndexWorkerError::Storage)?;
                open_derived_index_store_on_worker(Arc::new(inner), DEFAULT_BATCH_LIMITS, 1)
            }),
            bundle: IndexBundleDirective::None,
            facts_rx: Some(facts_rx),
            facts_charge: Some(facts_charge),
            query_charge: None,
            facts_gap: Some(facts_gap),
            cpu: None,
        };

        let worker = DerivedIndexWorker::spawn_with_open(
            Arc::clone(&runtime),
            spec,
            Arc::clone(&lifecycle),
            Generation::new(1),
            tip_reader,
            None,
            tree_reader,
            Some(body_store),
            HistoryAccess::new(
                Arc::new(RetentionRegistry::new()),
                RetentionBudget::Unlimited,
            ),
            Some(body_source),
            Arc::new(TestProbe),
            Arc::new(TestIndexAhead),
            shutdown.reader(),
            wake_rx,
        )
        .expect("worker spawns");

        let mut undo_map = HashMap::new();
        undo_map.insert(
            (genesis.txdata[0].compute_txid().to_byte_array(), 0),
            (50_000_000, FactsScript::copy_from_slice(&[0x51])),
        );

        let facts0 = block_to_facts(&genesis, 0, 1, &undo_map);
        let facts1 = block_to_facts(&b1, 1, 2, &undo_map);
        let facts2 = block_to_facts(&b2, 2, 3, &undo_map);

        facts_tx.send(Arc::new(facts0)).expect("send facts0");
        facts_tx.send(Arc::new(facts1)).expect("send facts1");
        facts_tx.send(Arc::new(facts2)).expect("send facts2");
        let _ = wake_tx.try_send(());

        let start = Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("timed out waiting for index catch up");
            }
            if let Ok(info) = adapter.index_info() {
                if info.synced && info.best_block_height == 2 {
                    assert_eq!(info.applied_height, 2);
                    assert_eq!(info.verified_height, 2);
                    assert_eq!(info.coverage_height, 2);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        // PRJ-01
        let reads = load_counter.load(Ordering::SeqCst);
        assert_eq!(
            reads, 0,
            "live index path must read zero block bodies, but read {reads}"
        );
        assert_eq!(
            source_calls.load(Ordering::SeqCst),
            0,
            "live index path must not read bodies through the body source either"
        );

        let b1_txid = Txid::from(Hash256::from_le_bytes(
            &b1.txdata[1].compute_txid().to_byte_array(),
        ));
        let queried = adapter.transaction(&b1_txid).expect("query transaction");
        assert!(
            queried.is_some(),
            "transaction from facts must be queryable"
        );

        shutdown.trigger();
        worker.join();
    }
}
mod live_rows {
    //! Committed-facts rows and the batch byte limit: `PRJ-05`.

    use crate::support::TestError;
    use std::sync::Arc;

    use bitcoin_rs_projection::{
        HEADER_ROW_SIZE, IndexCapabilities, IndexWriter, PreparedBatch, PreparedBatchLimits,
    };
    use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, TxFacts};
    use bitcoin_rs_storage::{FactsScript, RocksDbStore};

    fn coinbase_block(height: u32, outputs: u32) -> Result<CommittedBlock, TestError> {
        let mut created = Vec::new();
        for vout in 0..outputs {
            created.push(CreatedOutput {
                vout,
                value: 1_000 + u64::from(vout),
                script: FactsScript::copy_from_slice(&[0x51, u8::try_from(vout)?]),
            });
        }
        let mut txid = [0xC0; 32];
        txid[..4].copy_from_slice(&height.to_be_bytes());
        Ok(CommittedBlock {
            height,
            hash: [u8::try_from(height)?; 32],
            parent_hash: [0; 32],
            header: [0; 80],
            txs: vec![TxFacts {
                txid,
                offset: 81,
                len: 100,
                inputs: Vec::new(),
                outputs: created,
            }],
        })
    }

    fn writer() -> Result<(tempfile::TempDir, IndexWriter<RocksDbStore>), TestError> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        Ok((dir, IndexWriter::open(store, 1)?))
    }

    #[test]
    fn new_unspent_outputs_insert_one_row_each_and_delete_nothing() -> Result<(), TestError> {
        let (_dir, writer) = writer()?;
        let block = coinbase_block(5, 3)?;
        let prepared = writer.prepare_block_from_facts(IndexCapabilities::SCRIPT_LIVE, block)?;
        assert_eq!(
            prepared.row_count,
            1 + 3,
            "one header row plus one insert per new unspent output; no self-deletes"
        );
        Ok(())
    }

    #[test]
    fn tail_rows_count_toward_the_batch_byte_limit() -> Result<(), TestError> {
        let (_dir, writer) = writer()?;
        let caps = IndexCapabilities::HISTORICAL;
        let first = writer.prepare_block_from_facts(caps, coinbase_block(5, 2)?)?;
        let second = writer.prepare_block_from_facts(caps, coinbase_block(6, 2)?)?;
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: 2 * HEADER_ROW_SIZE,
        });
        assert!(
            batch.try_push(first).is_ok(),
            "the first block is always admitted"
        );
        assert!(
            batch.is_full(),
            "one block's tail rows plus its header reach the two-header byte limit"
        );
        assert!(
            batch.try_push(second).is_err(),
            "a full batch refuses the next block"
        );
        Ok(())
    }

    #[test]
    fn live_reader_distinguishes_full_hashes_with_the_same_scan_prefix() -> Result<(), TestError> {
        use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid};
        use bitcoin_rs_projection::{IndexWatermark, ScriptHash, ScriptLiveCoin, ScriptLiveRow};

        let (_dir, writer) = writer()?;
        let first = ScriptHash::from_byte_array([0x11; 32]);
        let mut colliding = [0x11; 32];
        colliding[31] = 0x22;
        let second = ScriptHash::from_byte_array(colliding);
        let a = OutPoint::new(Txid(Hash256::from_le_bytes(&[1; 32])), 0);
        let b = OutPoint::new(Txid(Hash256::from_le_bytes(&[2; 32])), 0);
        let mut rows = Vec::new();
        for (hash, outpoint) in [(first, a), (second, b)] {
            let mut row = ScriptLiveRow::new(hash, &outpoint).as_bytes().to_vec();
            row.extend_from_slice(&ScriptLiveCoin::new(hash, 100, 0, false).encode_value()?);
            rows.push(row);
        }
        writer.stage_script_live_rows(&mut rows.into_iter())?;
        writer.publish_script_live_seed(IndexWatermark {
            height: 0,
            hash: [0; 32],
        })?;
        assert_eq!(writer.indexer().iter_live_outpoints(first)?, vec![a]);
        assert_eq!(writer.indexer().iter_live_outpoints(second)?, vec![b]);
        Ok(())
    }
}
mod planned_bytes {
    //! The bytes a prepared batch plans bound every write the commit hands the
    //! store. The fixture spends an output created earlier in the same batch and
    //! pays a script the chain already used, so the tail append writes a spend
    //! row and an undo-log prior that a plan built from an empty tail would miss.

    use std::sync::Arc;

    use bitcoin_rs_consensus::primitives::encode::double_sha256;
    use bitcoin_rs_projection::{
        IndexCapabilities, IndexWriter, PreparedBatch, PreparedBatchLimits, PreparedBlock,
        SpentCoin, SpentCoins,
    };
    use bitcoin_rs_storage::{
        BatchOp, BufferedWriteBatch, ColumnFamily, KvIter, KvSnapshot, KvStore, PrefixScan,
        PrefixScanLimit, StorageError, WriteCondition,
    };
    use parking_lot::Mutex;

    use crate::support::TestError;
    use crate::support::common::MemoryStore;

    const COINBASE_VALUE: u64 = 50 * 100_000_000;
    const CHILD_VALUE: u64 = COINBASE_VALUE - 1_000;
    const OP_TRUE: [u8; 1] = [0x51];
    const P2WPKH: [u8; 22] = [
        0x00, 0x14, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    ];

    #[derive(Default)]
    struct RecordingStore {
        inner: MemoryStore,
        committed_bytes: Mutex<Vec<usize>>,
    }

    impl RecordingStore {
        fn record_and_replay(&self, batch: BufferedWriteBatch) -> BufferedWriteBatch {
            let ops = batch.into_ops();
            let total = ops
                .iter()
                .map(op_bytes)
                .fold(0_usize, usize::saturating_add);
            self.committed_bytes.lock().push(total);
            let mut replayed = self.inner.new_batch();
            for op in ops {
                match op {
                    BatchOp::Put { cf, key, value } => replayed.put_value(cf, &key, value),
                    BatchOp::Delete { cf, key } => replayed.delete(cf, &key),
                    BatchOp::DeleteRange { cf, start, end } => {
                        replayed.delete_range(cf, &start, &end)
                    }
                }
            }
            replayed
        }
    }

    fn op_bytes(op: &BatchOp) -> usize {
        match op {
            BatchOp::Put { key, value, .. } => key.len().saturating_add(value.len()),
            BatchOp::Delete { key, .. } => key.len(),
            BatchOp::DeleteRange { start, end, .. } => start.len().saturating_add(end.len()),
        }
    }

    impl KvStore for RecordingStore {
        fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get(cf, key)
        }

        fn iter_prefix<'a>(
            &'a self,
            cf: ColumnFamily,
            prefix: &[u8],
        ) -> Result<KvIter<'a>, StorageError> {
            self.inner.iter_prefix(cf, prefix)
        }

        fn scan_prefix_from_bounded(
            &self,
            cf: ColumnFamily,
            prefix: &[u8],
            start: &[u8],
            limit: PrefixScanLimit,
        ) -> Result<PrefixScan, StorageError> {
            self.inner
                .scan_prefix_from_bounded(cf, prefix, start, limit)
        }

        fn new_batch(&self) -> BufferedWriteBatch {
            self.inner.new_batch()
        }

        fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
            self.inner.write(self.record_and_replay(batch))
        }

        fn write_durable(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
            self.inner.write_durable(self.record_and_replay(batch))
        }

        fn write_durable_if(
            &self,
            conditions: &[WriteCondition<'_>],
            batch: BufferedWriteBatch,
        ) -> Result<bool, StorageError> {
            self.inner
                .write_durable_if(conditions, self.record_and_replay(batch))
        }

        fn flush(&self) -> Result<(), StorageError> {
            self.inner.flush()
        }

        fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
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

        fn delete_range(
            &self,
            cf: ColumnFamily,
            start: &[u8],
            end: &[u8],
        ) -> Result<(), StorageError> {
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

    struct NoCoins;

    impl SpentCoins for NoCoins {
        fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
            None
        }
    }

    struct FirstCoinbase {
        txid: [u8; 32],
    }

    impl SpentCoins for FirstCoinbase {
        fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<SpentCoin<'_>> {
            (txid == &self.txid && vout == 0).then_some(SpentCoin {
                script: &OP_TRUE,
                value: COINBASE_VALUE,
                height: 1,
                coinbase: true,
            })
        }
    }

    fn legacy_tx(inputs: &[([u8; 32], u32, Vec<u8>)], outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&1_i32.to_le_bytes());
        out.push(u8::try_from(inputs.len()).unwrap_or(u8::MAX));
        for (txid, vout, script_sig) in inputs {
            out.extend_from_slice(txid);
            out.extend_from_slice(&vout.to_le_bytes());
            out.push(u8::try_from(script_sig.len()).unwrap_or(u8::MAX));
            out.extend_from_slice(script_sig);
            out.extend_from_slice(&u32::MAX.to_le_bytes());
        }
        out.push(u8::try_from(outputs.len()).unwrap_or(u8::MAX));
        for (value, script) in outputs {
            out.extend_from_slice(&value.to_le_bytes());
            out.push(u8::try_from(script.len()).unwrap_or(u8::MAX));
            out.extend_from_slice(script);
        }
        out.extend_from_slice(&0_u32.to_le_bytes());
        out
    }

    struct Block {
        body: Vec<u8>,
        hash: [u8; 32],
    }

    fn block(prev: [u8; 32], height: u32, txs: &[Vec<u8>]) -> Block {
        let mut header = [0_u8; 80];
        header[..4].copy_from_slice(&1_i32.to_le_bytes());
        header[4..36].copy_from_slice(&prev);
        header[68..72].copy_from_slice(&height.to_le_bytes());
        header[72..76].copy_from_slice(&0x207f_ffff_u32.to_le_bytes());
        header[76..80].copy_from_slice(&height.to_le_bytes());
        let hash = double_sha256(&header).to_le_bytes();
        let mut body = header.to_vec();
        body.push(u8::try_from(txs.len()).unwrap_or(u8::MAX));
        for tx in txs {
            body.extend_from_slice(tx);
        }
        Block { body, hash }
    }

    struct Chain {
        first: Block,
        second: Block,
        cb1_txid: [u8; 32],
    }

    fn chain() -> Chain {
        let cb1 = legacy_tx(
            &[([0; 32], u32::MAX, vec![0x01, 0x01])],
            &[(COINBASE_VALUE, OP_TRUE.to_vec())],
        );
        let first = block([0; 32], 0, std::slice::from_ref(&cb1));
        let cb1_txid = double_sha256(&cb1).to_le_bytes();

        let cb2 = legacy_tx(
            &[([0; 32], u32::MAX, vec![0x02, 0x02, 0x00])],
            &[(COINBASE_VALUE, OP_TRUE.to_vec())],
        );
        let spend = legacy_tx(
            &[(cb1_txid, 0, Vec::new())],
            &[(CHILD_VALUE, P2WPKH.to_vec())],
        );
        let second = block(first.hash, 1, &[cb2, spend]);
        Chain {
            first,
            second,
            cb1_txid,
        }
    }

    fn prepare_pair(
        writer: &IndexWriter<RecordingStore>,
        caps: IndexCapabilities,
        chain: &Chain,
    ) -> Result<[PreparedBlock; 2], TestError> {
        let first = writer.prepare_block_with_spent_scripts(
            caps,
            0,
            chain.first.hash,
            &chain.first.body,
            &NoCoins,
        )?;
        let second = writer.prepare_block_with_spent_scripts(
            caps,
            1,
            chain.second.hash,
            &chain.second.body,
            &FirstCoinbase {
                txid: chain.cb1_txid,
            },
        )?;
        Ok([first, second])
    }

    // IDX-06
    #[test]
    fn planned_bytes_bound_every_write_of_a_batch() -> Result<(), TestError> {
        let chain = chain();
        let caps = IndexCapabilities::HISTORICAL.with_compact_filters(true);
        let store = Arc::new(RecordingStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;

        let mut measure = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        for prepared in prepare_pair(&writer, caps, &chain)? {
            assert!(
                measure.try_push(prepared).is_ok(),
                "an unbounded batch admits both blocks"
            );
        }
        let limit = measure.encoded_bytes();

        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: limit,
        });
        for prepared in prepare_pair(&writer, caps, &chain)? {
            assert!(
                batch.try_push(prepared).is_ok(),
                "a batch admitted at its own planned size is admitted again"
            );
        }
        assert!(limit > 0, "the fixture must plan a nonzero batch");

        writer.commit_forward(batch)?;
        let written = store
            .committed_bytes
            .lock()
            .last()
            .copied()
            .ok_or_else(|| std::io::Error::other("the commit recorded no write"))?;
        assert!(written > 0, "the fixture must write a nonzero batch");
        assert!(
            written <= limit,
            "the batch's writes must fit its planned bytes: wrote {written}, planned {limit}"
        );
        Ok(())
    }
}
mod portable_bundle {
    #![expect(
        clippy::expect_used,
        reason = "test: fixture setup failures abort the test with context"
    )]

    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use arc_swap::{ArcSwap, ArcSwapOption};
    use bitcoin::{
        Amount, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
        block::{Header as BtcHeader, Version},
        consensus::encode::serialize,
        hashes::Hash as _,
        pow::CompactTarget,
        script::Builder,
    };
    use bitcoin_rs_consensus::latch::LatchWriter;
    use bitcoin_rs_consensus::primitives::{BlockHash, Hash256, Network, Txid};
    use bitcoin_rs_execution::chain::{
        BlockTree, BlockTreeReader, ChainTxCount, NodeStatus, TipReader, TipSnapshot,
    };
    use bitcoin_rs_projection::portable::{
        IndexBundleDirective, IndexBundleRequest, ManifestArtifactTarget, SpillBudget,
        attach_tx_lookup_artifact,
    };
    use bitcoin_rs_projection::reconcile::{ChainCursorSource, ConsumerCursor};
    use bitcoin_rs_projection::runtime::{
        DEFAULT_BATCH_LIMITS, DerivedIndexLifecycle, DerivedIndexOpenSpec,
        DerivedIndexQueryAdapter, DerivedIndexRuntime, DerivedIndexWorker, Generation,
        IndexAheadError, IndexAheadSink, open_derived_index_store_on_worker,
    };
    use bitcoin_rs_projection::{
        DerivedIndexQuery, IndexCapabilities, IndexCapability, IndexReader, IndexWatermark,
        Indexer, index_format_version,
    };
    use bitcoin_rs_storage::block_body::BlockBodyStore;
    use bitcoin_rs_storage::block_body::{BlockBodyReadError, BlockBodySource};
    use bitcoin_rs_storage::pruning::{HistoryAccess, RetentionBudget, RetentionRegistry};
    use bitcoin_rs_storage::{
        BatchOp, BufferedWriteBatch, ColumnFamily, KvIter, KvPair, KvSnapshot, KvStore, PrefixScan,
        PrefixScanLimit, RocksDbStore, StorageBackend, StorageError, WriteCondition,
    };
    use parking_lot::RwLock;

    const MANIFEST: &str = "manifest.json";
    const ARTIFACT: &str = "txlookup-v1.dat";
    const STORE_CACHE_BYTES: u64 = 8 << 20;
    const CANCEL_POLL_RECORDS: usize = 4_096;
    const IMPORT_BATCH_ROWS: usize = 65_536;

    static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);

    type BodyMap = HashMap<(u32, [u8; 32]), Vec<u8>>;

    struct ChainFixture {
        tree: Arc<RwLock<BlockTree>>,
        bodies: Arc<BodyMap>,
        tip: Arc<TipSnapshot>,
        txids: Vec<(Txid, u32)>,
        block_hashes: Vec<Hash256>,
    }

    impl ChainFixture {
        fn new(blocks: u32, extra: usize) -> Self {
            let mut tree = BlockTree::new();
            let mut bodies = BodyMap::new();
            let mut txids = Vec::new();
            let mut block_hashes = Vec::new();
            let mut prev = [0_u8; 32];
            let mut tip_id = None;
            for height in 0..=blocks {
                let block = mine_block(prev, height, if height == 0 { 0 } else { extra });
                let bytes = serialize(&block);
                let parsed: bitcoin_rs_consensus::primitives::Block =
                    bitcoin_rs_consensus::primitives::deserialize(&bytes)
                        .expect("fixture block decodes");
                let header: bitcoin_rs_consensus::primitives::Header =
                    bitcoin_rs_consensus::primitives::deserialize(&serialize(&block.header))
                        .expect("80-byte header");
                let id = tree
                    .insert_header(header, NodeStatus::HeaderValid)
                    .expect("fixture header links to its parent");
                tree.record_applied_tx_count(
                    id,
                    u64::try_from(parsed.txs.len()).expect("transaction count fits u64"),
                )
                .expect("fixture node exists");
                txids.extend(parsed.txids().into_iter().map(|txid| (txid, height)));
                let hash = block.block_hash().to_byte_array();
                block_hashes.push(Hash256::from_le_bytes(&hash));
                bodies.insert((height, hash), bytes);
                prev = hash;
                tip_id = Some(id);
            }
            let tip_id = tip_id.expect("genesis is always mined");
            let tip = {
                let node = tree.node(tip_id).expect("tip node");
                Arc::new(TipSnapshot {
                    tip_id,
                    height: node.height,
                    chainwork: node.chainwork,
                    hash: node.hash,
                    chain_tx_count: node.chain_tx_count,
                })
            };
            Self {
                tree: Arc::new(RwLock::new(tree)),
                bodies: Arc::new(bodies),
                tip,
                txids,
                block_hashes,
            }
        }

        fn restarted(self) -> Self {
            {
                let mut tree = self.tree.write();
                let mut cursor = tree.node(self.tip.tip_id).expect("tip node").parent;
                while let Some(id) = cursor {
                    cursor = tree.node(id).expect("ancestor node").parent;
                    tree.restore_chain_tx_count(id, ChainTxCount::UNKNOWN)
                        .expect("ancestor node exists");
                }
            }
            self
        }

        fn tx_row_keys(&self) -> usize {
            self.txids
                .iter()
                .map(|(txid, height)| {
                    let bytes = Hash256::from(*txid).to_le_bytes();
                    let mut prefix = [0_u8; 8];
                    prefix.copy_from_slice(&bytes[..8]);
                    (prefix, *height)
                })
                .collect::<HashSet<_>>()
                .len()
        }

        fn txs_through(&self, height: u32) -> u64 {
            u64::try_from(
                self.txids
                    .iter()
                    .filter(|(_, tx_height)| *tx_height <= height)
                    .count(),
            )
            .expect("tx count fits u64")
        }

        fn tip_watermark(&self) -> IndexWatermark {
            IndexWatermark {
                height: self.tip.height,
                hash: self.tip.hash.to_le_bytes(),
            }
        }
    }

    fn coinbase(height: u32) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: Builder::new()
                    .push_int(i64::from(height))
                    .push_int(0)
                    .into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    fn filler(height: u32, index: usize) -> Transaction {
        let index = u32::try_from(index).expect("filler index fits u32");
        let mut seed = [0x5a_u8; 32];
        seed[..4].copy_from_slice(&height.to_le_bytes());
        seed[4..8].copy_from_slice(&index.to_le_bytes());
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array(seed),
                    vout: index,
                },
                script_sig: Builder::new()
                    .push_int(i64::from(height))
                    .push_int(i64::from(index))
                    .into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    fn mine_block(prev: [u8; 32], height: u32, extra: usize) -> bitcoin::Block {
        let mut txdata = Vec::with_capacity(extra + 1);
        txdata.push(coinbase(height));
        txdata.extend((0..extra).map(|index| filler(height, index)));
        let mut block = bitcoin::Block {
            header: BtcHeader {
                version: Version::ONE,
                prev_blockhash: bitcoin::BlockHash::from_byte_array(prev),
                merkle_root: TxMerkleNode::all_zeros(),
                time: height,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata,
        };
        block.header.merkle_root = block
            .compute_merkle_root()
            .unwrap_or_else(TxMerkleNode::all_zeros);
        while block.header.validate_pow(block.header.target()).is_err() {
            block.header.nonce = block.header.nonce.wrapping_add(1);
        }
        block
    }

    #[derive(Default)]
    struct Probe {
        reconciling: AtomicBool,
    }

    impl ChainCursorSource for Probe {
        fn cursor(&self) -> ConsumerCursor {
            self.reconciling.store(true, Ordering::Release);
            ConsumerCursor {
                epoch: 0,
                sequence: 0,
                height: 0,
                hash: Hash256::from_le_bytes(&[0_u8; 32]),
            }
        }
    }

    struct NoIndexAhead;

    impl IndexAheadSink for NoIndexAhead {
        fn report_index_ahead(
            &self,
            _capability: &str,
            _index_height: u32,
            _tip_height: u32,
            _tip_hash_be: &str,
            _index_hash_be: &str,
            _depth: u32,
            _unix_secs: u64,
        ) -> Result<(), IndexAheadError> {
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct BodyLoadCounter {
        total: AtomicU64,
        per_height: Mutex<HashMap<u32, u64>>,
    }

    struct SourceBodies {
        bodies: Arc<BodyMap>,
        hidden: HashSet<u32>,
        trip: Option<Arc<LatchWriter>>,
        witness: Option<(PathBuf, Arc<AtomicBool>)>,
        loads: Option<Arc<BodyLoadCounter>>,
    }

    impl SourceBodies {
        fn body(&self, height: u32, hash: BlockHash) -> Option<&[u8]> {
            if let Some((path, seen)) = &self.witness {
                if path.exists() {
                    seen.store(true, Ordering::Release);
                }
            }
            if let Some(trip) = &self.trip {
                trip.trigger();
            }
            if self.hidden.contains(&height) {
                return None;
            }
            self.bodies
                .get(&(height, Hash256::from(hash).to_le_bytes()))
                .map(Vec::as_slice)
        }
    }

    impl BlockBodySource for SourceBodies {
        fn block_body(
            &self,
            height: u32,
            hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, BlockBodyReadError> {
            if let Some(loads) = &self.loads {
                loads.total.fetch_add(1, Ordering::Relaxed);
                *loads
                    .per_height
                    .lock()
                    .expect("body load counts are readable")
                    .entry(height)
                    .or_default() += 1;
            }
            Ok(self.body(height, hash).map(<[u8]>::to_vec))
        }

        fn block_body_range(
            &self,
            height: u32,
            hash: BlockHash,
            offset: u32,
            len: u32,
        ) -> Option<Vec<u8>> {
            let body = self.body(height, hash)?;
            let start = usize::try_from(offset).ok()?;
            let end = start.checked_add(usize::try_from(len).ok()?)?;
            body.get(start..end).map(<[u8]>::to_vec)
        }
    }

    struct StoreBodies {
        bodies: Arc<BodyMap>,
        serve: bool,
        from_height: u32,
        probe: Arc<Probe>,
    }

    impl BlockBodyStore for StoreBodies {
        fn persist_block_body(
            &self,
            _height: u32,
            _hash: Hash256,
            _body: &[u8],
        ) -> Result<(), StorageError> {
            Ok(())
        }

        fn load_block_body(
            &self,
            height: u32,
            hash: Hash256,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            self.probe.reconciling.store(true, Ordering::Release);
            if !self.serve || height < self.from_height {
                return Ok(None);
            }
            Ok(self.bodies.get(&(height, hash.to_le_bytes())).cloned())
        }

        fn undo_record(
            &self,
            _height: u32,
            _hash: Hash256,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(None)
        }

        fn sync(&self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    struct CrashAfterBulkImport {
        inner: RocksDbStore,
        crashed: AtomicBool,
    }

    impl CrashAfterBulkImport {
        fn admit(&self, batch: BufferedWriteBatch) -> Result<(Vec<BatchOp>, bool), StorageError> {
            if self.crashed.load(Ordering::Acquire) {
                return Err(StorageError::backend(
                    "injected crash after a bulk import batch",
                ));
            }
            let ops = batch.into_ops();
            let tx_rows = ops
                .iter()
                .filter(|op| {
                    matches!(
                        op,
                        BatchOp::Put {
                            cf: ColumnFamily::TxConfirmed,
                            ..
                        }
                    )
                })
                .count();
            Ok((ops, tx_rows >= IMPORT_BATCH_ROWS / 2))
        }

        fn rebuild(ops: Vec<BatchOp>) -> BufferedWriteBatch {
            let mut batch = BufferedWriteBatch::default();
            for op in ops {
                match op {
                    BatchOp::Put { cf, key, value } => batch.put_value(cf, &key, value),
                    BatchOp::Delete { cf, key } => batch.delete(cf, &key),
                    BatchOp::DeleteRange { cf, start, end } => batch.delete_range(cf, &start, &end),
                }
            }
            batch
        }

        fn crash_if(&self, bulk: bool) {
            if bulk {
                self.crashed.store(true, Ordering::Release);
            }
        }
    }

    impl KvStore for CrashAfterBulkImport {
        fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get(cf, key)
        }

        fn iter_prefix<'a>(
            &'a self,
            cf: ColumnFamily,
            prefix: &[u8],
        ) -> Result<KvIter<'a>, StorageError> {
            self.inner.iter_prefix(cf, prefix)
        }

        fn scan_prefix_from_bounded(
            &self,
            cf: ColumnFamily,
            prefix: &[u8],
            start: &[u8],
            limit: PrefixScanLimit,
        ) -> Result<PrefixScan, StorageError> {
            self.inner
                .scan_prefix_from_bounded(cf, prefix, start, limit)
        }

        fn new_batch(&self) -> BufferedWriteBatch {
            self.inner.new_batch()
        }

        fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
            let (ops, bulk) = self.admit(batch)?;
            self.inner.write(Self::rebuild(ops))?;
            self.crash_if(bulk);
            Ok(())
        }

        fn write_durable(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
            let (ops, bulk) = self.admit(batch)?;
            self.inner.write_durable(Self::rebuild(ops))?;
            self.crash_if(bulk);
            Ok(())
        }

        fn write_durable_if(
            &self,
            conditions: &[WriteCondition<'_>],
            batch: BufferedWriteBatch,
        ) -> Result<bool, StorageError> {
            let (ops, bulk) = self.admit(batch)?;
            let applied = self
                .inner
                .write_durable_if(conditions, Self::rebuild(ops))?;
            self.crash_if(applied && bulk);
            Ok(applied)
        }

        fn flush(&self) -> Result<(), StorageError> {
            self.inner.flush()
        }

        fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
            self.inner.snapshot()
        }

        fn arm_persist_fault(&self, fault: bitcoin_rs_storage::PersistFault) {
            self.inner.arm_persist_fault(fault);
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
            if self.crashed.load(Ordering::Acquire) {
                return Err(StorageError::backend("injected post-bulk crash"));
            }
            let count = self.inner.ingest_sorted(cf, rows, scratch)?;
            self.crashed.store(true, Ordering::Release);
            Ok(count)
        }

        fn delete_range(
            &self,
            cf: ColumnFamily,
            start: &[u8],
            end: &[u8],
        ) -> Result<(), StorageError> {
            self.inner.delete_range(cf, start, end)
        }

        fn checkpoint(&self, dir: &std::path::Path) -> Result<(), StorageError> {
            self.inner.checkpoint(dir)
        }

        fn engine_cache_bytes(&self) -> u64 {
            self.inner.engine_cache_bytes()
        }
    }

    #[derive(Clone, Copy, Default)]
    enum Bodies {
        #[default]
        All,
        Hidden(u32),
        NoSource,
    }

    #[derive(Default)]
    struct Start {
        bundle: IndexBundleDirective,
        backfill: bool,
        backfill_from: u32,
        bodies: Bodies,
        cancel_on_body_read: bool,
        crash_after_bulk_import: bool,
        witness: Option<(PathBuf, Arc<AtomicBool>)>,
        body_loads: Option<Arc<BodyLoadCounter>>,
    }

    struct Node {
        runtime: Arc<DerivedIndexRuntime>,
        lifecycle: Arc<ArcSwap<DerivedIndexLifecycle>>,
        adapter: DerivedIndexQueryAdapter,
        probe: Arc<Probe>,
        worker: Option<DerivedIndexWorker>,
    }

    fn restore(dir: &Path) -> IndexBundleDirective {
        IndexBundleDirective::Restore(IndexBundleRequest {
            dir: dir.to_path_buf(),
            network: Network::Regtest,
        })
    }

    fn export(dir: &Path) -> IndexBundleDirective {
        IndexBundleDirective::Export(IndexBundleRequest {
            dir: dir.to_path_buf(),
            network: Network::Regtest,
        })
    }

    impl Node {
        fn start(fixture: &ChainFixture, data_dir: &Path, start: Start) -> Self {
            let epoch = NEXT_EPOCH.fetch_add(1, Ordering::Relaxed);
            let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
            let runtime = DerivedIndexRuntime::new(wake_tx);
            let lifecycle = Arc::new(ArcSwap::from_pointee(DerivedIndexLifecycle::Opening));
            let adapter = DerivedIndexQueryAdapter::new(Arc::clone(&lifecycle));
            let probe = Arc::new(Probe::default());
            let shutdown = Arc::new(LatchWriter::new());
            let crash = start.crash_after_bulk_import;
            let spec = DerivedIndexOpenSpec {
                scripthash_limit: bitcoin_rs_projection::runtime::DEFAULT_SCRIPTHASH_LIMIT,
                data_dir: data_dir.to_path_buf(),
                namespace: "txindex",
                storage_backend: StorageBackend::RocksDb,
                epoch,
                enabled: IndexCapabilities::TX_LOOKUP,
                rollback_rebuild_cutover: u32::MAX,
                canonical_data_root: data_dir.to_path_buf(),
                open_store: Arc::new(move |dir| {
                    let inner = RocksDbStore::open_with_cache(dir, STORE_CACHE_BYTES).map_err(
                        bitcoin_rs_projection::runtime::DerivedIndexWorkerError::Storage,
                    )?;
                    if crash {
                        let store = Arc::new(CrashAfterBulkImport {
                            inner,
                            crashed: AtomicBool::new(false),
                        });
                        open_derived_index_store_on_worker(store, DEFAULT_BATCH_LIMITS, epoch)
                    } else {
                        open_derived_index_store_on_worker(
                            Arc::new(inner),
                            DEFAULT_BATCH_LIMITS,
                            epoch,
                        )
                    }
                }),
                bundle: start.bundle,
                facts_rx: None,
                facts_charge: None,
                query_charge: None,
                facts_gap: None,
                cpu: None,
            };
            let body_store: Arc<dyn BlockBodyStore> = Arc::new(StoreBodies {
                bodies: Arc::clone(&fixture.bodies),
                serve: start.backfill,
                from_height: start.backfill_from,
                probe: Arc::clone(&probe),
            });
            let body_source: Option<Arc<dyn BlockBodySource>> = match start.bodies {
                Bodies::NoSource => None,
                Bodies::All | Bodies::Hidden(_) => Some(Arc::new(SourceBodies {
                    bodies: Arc::clone(&fixture.bodies),
                    hidden: match start.bodies {
                        Bodies::Hidden(height) => HashSet::from([height]),
                        Bodies::All | Bodies::NoSource => HashSet::new(),
                    },
                    trip: start.cancel_on_body_read.then(|| Arc::clone(&shutdown)),
                    witness: start.witness,
                    loads: start.body_loads,
                })),
            };
            let chain_events: Arc<dyn ChainCursorSource> = probe.clone();
            let index_ahead: Arc<dyn IndexAheadSink> = Arc::new(NoIndexAhead);
            let worker = DerivedIndexWorker::spawn_with_open(
                Arc::clone(&runtime),
                spec,
                Arc::clone(&lifecycle),
                Generation::new(epoch),
                TipReader::new(Arc::new(ArcSwapOption::new(Some(Arc::clone(&fixture.tip))))),
                None,
                BlockTreeReader::new(Arc::clone(&fixture.tree)),
                Some(body_store),
                HistoryAccess::new(
                    Arc::new(RetentionRegistry::new()),
                    RetentionBudget::Unlimited,
                ),
                body_source,
                chain_events,
                index_ahead,
                shutdown.reader(),
                wake_rx,
            )
            .expect("spawn txindex worker");
            Self {
                runtime,
                lifecycle,
                adapter,
                probe,
                worker: Some(worker),
            }
        }

        fn finished(&self) -> bool {
            self.worker
                .as_ref()
                .is_none_or(DerivedIndexWorker::is_finished)
        }

        fn failure(&self) -> Option<String> {
            match &**self.lifecycle.load() {
                DerivedIndexLifecycle::Failed(reason) => Some(reason.to_string()),
                _ => None,
            }
        }

        fn synced_at(&self, height: u32) -> bool {
            matches!(
                self.adapter.index_info(),
                Ok(info) if info.synced && info.best_block_height == height
            )
        }

        fn wait_synced(&self, height: u32) {
            wait_until("txindex synced at the tip", || {
                assert!(
                    !self.finished(),
                    "worker exited before sync: {:?}",
                    self.failure()
                );
                self.runtime.wake();
                self.synced_at(height)
            });
        }

        fn wait_reconciling(&self) {
            wait_until("worker to enter reconciliation", || {
                assert!(
                    !self.finished(),
                    "worker exited before reconciliation: {:?}",
                    self.failure()
                );
                self.runtime.wake();
                self.probe.reconciling.load(Ordering::Acquire)
            });
        }

        fn wait_finished(&self) {
            wait_until("worker exit", || self.finished());
        }

        fn stop(mut self) {
            if let Some(worker) = self.worker.take() {
                worker.join();
            }
        }
    }

    fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(300);
        while !ready() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    type LogicalTxRow = ([u8; 32], u32, [u8; 32], u32, u32);

    #[derive(Debug, PartialEq, Eq)]
    struct Durable {
        tx_confirmed: Vec<LogicalTxRow>,
        headers: Vec<KvPair>,
        watermark: Option<IndexWatermark>,
        floor: Option<u32>,
    }

    fn tx_lookup_rows(store: &RocksDbStore) -> Vec<LogicalTxRow> {
        use bitcoin_rs_projection::segment::format::{decode_tx_dir_key, decode_tx_dir_value};
        let mut rows: Vec<LogicalTxRow> = store
            .iter_prefix(ColumnFamily::TxDir, &[])
            .expect("iterate tx directory")
            .collect::<Result<Vec<_>, _>>()
            .expect("read tx directory")
            .into_iter()
            .filter_map(|(key, value)| {
                let (_gen, txid, height) = decode_tx_dir_key(&key)?;
                let (block_hash, _ordinal, offset, len) =
                    decode_tx_dir_value(&value).expect("tx directory value");
                Some((txid, height, block_hash, offset, len))
            })
            .collect();
        rows.sort_unstable();
        rows
    }

    fn durable(data_dir: &Path) -> Durable {
        let store = Arc::new(
            RocksDbStore::open_with_cache(data_dir.join("txindex"), STORE_CACHE_BYTES)
                .expect("reopen txindex store"),
        );
        let rows = |cf| {
            store
                .iter_prefix(cf, &[])
                .expect("iterate column family")
                .collect::<Result<Vec<_>, _>>()
                .expect("read column family")
        };
        let tx_confirmed = tx_lookup_rows(&store);
        let headers = rows(ColumnFamily::BlockHeaders);
        let indexer = Indexer::new(Arc::clone(&store));
        let snapshot = indexer.snapshot().expect("index snapshot");
        let watermark = snapshot
            .capability_watermark(IndexCapability::TxLookup)
            .expect("txlookup watermark");
        let floor = watermark.map(|_| {
            snapshot
                .capability_floor(IndexCapability::TxLookup)
                .expect("txlookup floor")
        });
        Durable {
            tx_confirmed,
            headers,
            watermark,
            floor,
        }
    }

    fn read_dir_files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files: Vec<_> = fs::read_dir(dir)
            .expect("list bundle directory")
            .map(|entry| {
                let path = entry.expect("directory entry").path();
                let bytes = fs::read(&path).expect("read bundle file");
                (path, bytes)
            })
            .collect();
        files.sort();
        files
    }

    fn copy_bundle(from: &Path, to: &Path) {
        fs::create_dir_all(to).expect("create bundle copy");
        for name in [MANIFEST, ARTIFACT] {
            fs::copy(from.join(name), to.join(name)).expect("copy bundle file");
        }
    }

    fn backfilled_source(fixture: &ChainFixture, source: &Path) -> Durable {
        let node = Node::start(
            fixture,
            source,
            Start {
                backfill: true,
                ..Start::default()
            },
        );
        node.wait_synced(fixture.tip.height);
        node.stop();
        let state = durable(source);
        assert_eq!(state.watermark, Some(fixture.tip_watermark()));
        assert_eq!(state.floor, Some(0));
        assert_eq!(state.tx_confirmed.len(), fixture.tx_row_keys());
        state
    }

    fn exported_bundle(fixture: &ChainFixture, source: &Path, bundle: &Path) {
        let node = Node::start(
            fixture,
            source,
            Start {
                bundle: export(bundle),
                backfill: true,
                ..Start::default()
            },
        );
        node.wait_reconciling();
        node.stop();
        assert!(
            bundle.join(MANIFEST).is_file(),
            "export published no manifest"
        );
        assert!(
            bundle.join(ARTIFACT).is_file(),
            "export published no artifact"
        );
    }

    fn assert_untouched_fresh(receiver: &Path) {
        let state = durable(receiver);
        assert!(
            state.tx_confirmed.is_empty(),
            "a refused or withheld restore wrote {} TxConfirmed rows",
            state.tx_confirmed.len()
        );
        assert_eq!(state.watermark, None);
    }

    // IDX-11
    #[test]
    fn export_then_restore_serves_the_same_queries_as_backfill() {
        let fixture = ChainFixture::new(6, 40);
        let root = tempfile::tempdir().expect("tempdir");
        let (source, receiver, bundle, again) = (
            root.path().join("source"),
            root.path().join("receiver"),
            root.path().join("bundle"),
            root.path().join("re-export"),
        );
        let source_state = backfilled_source(&fixture, &source);
        exported_bundle(&fixture, &source, &bundle);
        let bundle_files = read_dir_files(&bundle);

        let source_node = Node::start(
            &fixture,
            &source,
            Start {
                backfill: true,
                ..Start::default()
            },
        );
        let restored = Node::start(
            &fixture,
            &receiver,
            Start {
                bundle: restore(&bundle),
                ..Start::default()
            },
        );
        source_node.wait_synced(fixture.tip.height);
        restored.wait_synced(fixture.tip.height);
        for (txid, height) in &fixture.txids {
            let expected = source_node.adapter.transaction_block(txid);
            let expected_identity = bitcoin_rs_projection::TransactionBlock {
                height: *height,
                hash: fixture.block_hashes
                    [usize::try_from(*height).expect("fixture height fits usize")],
            };
            let (source_tx, source_identity) = expected
                .as_ref()
                .expect("source lookup")
                .as_ref()
                .expect("source transaction");
            assert_eq!(source_tx.txid(), *txid);
            assert_eq!(*source_identity, expected_identity);
            assert_eq!(restored.adapter.transaction_block(txid), expected);
            let served = restored.adapter.transaction(txid);
            assert!(matches!(&served, Ok(Some(tx)) if tx.txid() == *txid));
            assert_eq!(served, source_node.adapter.transaction(txid));
        }
        let absent = Txid::from(Hash256::from_le_bytes(&[0xa5_u8; 32]));
        assert_eq!(restored.adapter.transaction(&absent), Ok(None));
        assert_eq!(source_node.adapter.transaction(&absent), Ok(None));
        assert_eq!(
            restored.adapter.index_info(),
            source_node.adapter.index_info()
        );
        restored.stop();
        source_node.stop();

        assert_eq!(durable(&receiver), source_state);
        assert_eq!(
            read_dir_files(&bundle),
            bundle_files,
            "restore mutated the bundle"
        );

        exported_bundle(&fixture, &receiver, &again);
        assert_eq!(
            fs::read(again.join(ARTIFACT)).expect("re-exported artifact"),
            fs::read(bundle.join(ARTIFACT)).expect("original artifact"),
        );
        assert_eq!(
            fs::read(again.join(MANIFEST)).expect("re-exported manifest"),
            fs::read(bundle.join(MANIFEST)).expect("original manifest"),
        );
    }

    #[test]
    fn restore_below_a_restarted_receivers_tip_then_reconciles_forward() {
        let bundle_chain = ChainFixture::new(5, 25);
        let receiver_chain = ChainFixture::new(7, 25).restarted();
        let base = bundle_chain.tip.height;
        assert!(
            receiver_chain
                .bodies
                .contains_key(&(base, bundle_chain.tip.hash.to_le_bytes())),
            "the receiver must hold the bundle's base block"
        );
        let root = tempfile::tempdir().expect("tempdir");
        let (source, truth, receiver, bundle) = (
            root.path().join("source"),
            root.path().join("truth"),
            root.path().join("receiver"),
            root.path().join("bundle"),
        );
        let source_state = backfilled_source(&bundle_chain, &source);
        exported_bundle(&bundle_chain, &source, &bundle);
        let truth_state = backfilled_source(&receiver_chain, &truth);

        let withheld = root.path().join("receiver-withheld");
        let node = Node::start(
            &receiver_chain,
            &withheld,
            Start {
                bundle: restore(&bundle),
                bodies: Bodies::Hidden(receiver_chain.tip.height),
                ..Start::default()
            },
        );
        node.wait_reconciling();
        node.stop();
        assert_untouched_fresh(&withheld);

        let node = Node::start(
            &receiver_chain,
            &receiver,
            Start {
                bundle: restore(&bundle),
                ..Start::default()
            },
        );
        node.wait_reconciling();
        node.stop();
        assert_eq!(
            durable(&receiver),
            source_state,
            "the bundle must be restored through its base"
        );

        let node = Node::start(
            &receiver_chain,
            &receiver,
            Start {
                backfill: true,
                backfill_from: base + 1,
                ..Start::default()
            },
        );
        node.wait_synced(receiver_chain.tip.height);
        for (txid, height) in &receiver_chain.txids {
            let (tx, identity) = node
                .adapter
                .transaction_block(txid)
                .expect("receiver lookup")
                .expect("receiver transaction");
            assert_eq!(tx.txid(), *txid);
            assert_eq!(
                identity,
                bitcoin_rs_projection::TransactionBlock {
                    height: *height,
                    hash: receiver_chain.block_hashes
                        [usize::try_from(*height).expect("fixture height fits usize")],
                }
            );
        }
        node.stop();
        assert_eq!(durable(&receiver), truth_state);
    }

    // IDX-11
    #[test]
    fn damaged_bundles_are_refused_before_any_write_or_reset() {
        type Damage = fn(&Path, u64);
        let fixture = ChainFixture::new(5, 30);
        let root = tempfile::tempdir().expect("tempdir");
        let (source, bundle) = (root.path().join("source"), root.path().join("bundle"));
        let source_state = backfilled_source(&fixture, &source);
        exported_bundle(&fixture, &source, &bundle);
        let artifact_len = fs::metadata(bundle.join(ARTIFACT))
            .expect("artifact metadata")
            .len();

        let damages: [(&str, Damage); 6] = [
            ("payload-bit-flip", |dir, len| {
                flip_byte(&dir.join(ARTIFACT), len - 1);
            }),
            ("header-bit-flip", |dir, _| {
                flip_byte(&dir.join(ARTIFACT), 10);
            }),
            ("artifact-truncated", |dir, len| {
                fs::OpenOptions::new()
                    .write(true)
                    .open(dir.join(ARTIFACT))
                    .and_then(|file| file.set_len(len - 1))
                    .expect("truncate artifact");
            }),
            ("artifact-extended", |dir, _| {
                let mut bytes = fs::read(dir.join(ARTIFACT)).expect("read artifact");
                bytes.push(0);
                fs::write(dir.join(ARTIFACT), bytes).expect("extend artifact");
            }),
            ("manifest-truncated", |dir, _| {
                let bytes = fs::read(dir.join(MANIFEST)).expect("read manifest");
                fs::write(dir.join(MANIFEST), &bytes[..bytes.len() / 2])
                    .expect("truncate manifest");
            }),
            ("artifact-missing", |dir, _| {
                fs::remove_file(dir.join(ARTIFACT)).expect("remove artifact");
            }),
        ];

        for (name, damage) in damages {
            let damaged = root.path().join(format!("bundle-{name}"));
            copy_bundle(&bundle, &damaged);
            damage(&damaged, artifact_len);
            let damaged_files = read_dir_files(&damaged);

            let receiver = root.path().join(format!("receiver-{name}"));
            let node = Node::start(
                &fixture,
                &receiver,
                Start {
                    bundle: restore(&damaged),
                    ..Start::default()
                },
            );
            node.wait_reconciling();
            assert!(
                !node.synced_at(fixture.tip.height),
                "{name}: a refused bundle made the index ready"
            );
            node.stop();
            assert_untouched_fresh(&receiver);
            assert_eq!(
                read_dir_files(&damaged),
                damaged_files,
                "{name}: bundle rewritten"
            );

            let ready = Node::start(
                &fixture,
                &source,
                Start {
                    bundle: restore(&damaged),
                    backfill: true,
                    ..Start::default()
                },
            );
            ready.wait_reconciling();
            ready.wait_synced(fixture.tip.height);
            ready.stop();
            assert_eq!(
                durable(&source),
                source_state,
                "{name}: ready index changed"
            );
        }
    }

    fn flip_byte(path: &Path, offset: u64) {
        let mut bytes = fs::read(path).expect("read artifact");
        let index = usize::try_from(offset).expect("offset fits usize");
        bytes[index] ^= 0x01;
        fs::write(path, bytes).expect("rewrite artifact");
    }

    fn digest_of(path: &Path) -> [u8; 32] {
        use sha2::Digest as _;
        sha2::Sha256::digest(fs::read(path).expect("read artifact")).into()
    }

    fn chain_headers(
        fixture: &ChainFixture,
        base_height: u32,
        base_hash: [u8; 32],
    ) -> Vec<[u8; 80]> {
        let tree = fixture.tree.read();
        let tip = tree
            .lookup(Hash256::from_le_bytes(&base_hash))
            .expect("base header");
        (0..=base_height)
            .map(|height| {
                let id = tree
                    .node_at_height_from(tip, height)
                    .expect("header on the active chain");
                let node = tree.node(id).expect("header node");
                let mut bytes = [0_u8; 80];
                bytes.copy_from_slice(
                    &bitcoin_rs_consensus::primitives::consensus_bytes(&node.header)[..80],
                );
                bytes
            })
            .collect()
    }

    fn manifest_target(
        artifact: &Path,
        base: IndexWatermark,
        sha256: [u8; 32],
        size_bytes: u64,
        chain_tx_count: u64,
    ) -> ManifestArtifactTarget {
        ManifestArtifactTarget {
            artifact_path: artifact.to_path_buf(),
            base_height: base.height,
            base_hash: base.hash,
            floor: 0,
            network: Network::Regtest,
            index_format: index_format_version(),
            sha256,
            size_bytes,
            chain_tx_count,
        }
    }

    fn open_receiver(root: &Path, name: &str) -> bitcoin_rs_projection::runtime::OpenDerivedIndex {
        let store = Arc::new(
            RocksDbStore::open_with_cache(root.join(name).join("txindex"), STORE_CACHE_BYTES)
                .expect("receiver store"),
        );
        open_derived_index_store_on_worker(
            store,
            DEFAULT_BATCH_LIMITS,
            NEXT_EPOCH.fetch_add(1, Ordering::Relaxed),
        )
        .expect("open receiver index")
    }

    // SNP-03, SNP-04, SNP-05
    #[test]
    fn manifest_artifact_attach_verifies_digest_header_and_base_before_ingest() {
        let fixture = ChainFixture::new(5, 30);
        let root = tempfile::tempdir().expect("tempdir");
        let (source, bundle) = (root.path().join("source"), root.path().join("bundle"));
        backfilled_source(&fixture, &source);
        exported_bundle(&fixture, &source, &bundle);
        let base = fixture.tip_watermark();
        let exported = bundle.join(ARTIFACT);
        let size = fs::metadata(&exported)
            .expect("exported artifact metadata")
            .len();
        let headers = chain_headers(&fixture, base.height, base.hash);
        let header_refs: Vec<&[u8; 80]> = headers.iter().collect();

        let attach = root.path().join("attach");
        fs::create_dir_all(&attach).expect("attach dir");
        fs::copy(&exported, attach.join(ARTIFACT)).expect("stage manifest artifact");
        let good = open_receiver(root.path(), "receiver-good");
        let records = attach_tx_lookup_artifact(
            good.writer(),
            &manifest_target(
                &attach.join(ARTIFACT),
                base,
                digest_of(&attach.join(ARTIFACT)),
                size,
                fixture.txs_through(base.height),
            ),
            &header_refs,
            &attach,
            &SpillBudget::new(u64::MAX),
        )
        .expect("a verified manifest artifact attaches");
        assert!(records > 0, "the attached artifact produced no rows");
        let (_, watermarks) = good
            .writer()
            .fenced_watermarks()
            .expect("receiver watermarks");
        assert_eq!(watermarks.tx_lookup, Some(base));

        let poisoned = root.path().join("attach-poisoned");
        fs::create_dir_all(&poisoned).expect("attach dir");
        fs::copy(&exported, poisoned.join(ARTIFACT)).expect("stage manifest artifact");
        let mut forged = digest_of(&poisoned.join(ARTIFACT));
        forged[0] ^= 0x01;
        let receiver = open_receiver(root.path(), "receiver-bad");
        let error = attach_tx_lookup_artifact(
            receiver.writer(),
            &manifest_target(
                &poisoned.join(ARTIFACT),
                base,
                forged,
                size,
                fixture.txs_through(base.height),
            ),
            &header_refs,
            &poisoned,
            &SpillBudget::new(u64::MAX),
        )
        .expect_err("a manifest artifact with a forged digest must be refused");
        assert!(
            matches!(
                error,
                bitcoin_rs_projection::portable::IndexBundleError::ArtifactHash { .. }
            ),
            "got {error:?}"
        );

        let wrong_base = IndexWatermark {
            height: base.height - 1,
            hash: base.hash,
        };
        let error = attach_tx_lookup_artifact(
            receiver.writer(),
            &manifest_target(
                &poisoned.join(ARTIFACT),
                wrong_base,
                digest_of(&poisoned.join(ARTIFACT)),
                size,
                fixture.txs_through(wrong_base.height),
            ),
            &header_refs,
            &poisoned,
            &SpillBudget::new(u64::MAX),
        )
        .expect_err("a manifest artifact from another base must be refused");
        assert!(
            matches!(
                error,
                bitcoin_rs_projection::portable::IndexBundleError::ArtifactHeader { .. }
            ),
            "got {error:?}"
        );

        drop(good);
        drop(receiver);
        assert_untouched_fresh(&root.path().join("receiver-bad"));
    }
    // SNP-05
    #[test]
    fn small_budget_tx_lookup_restore_matches_backfill() {
        let fixture = ChainFixture::new(6, 40);
        let root = tempfile::tempdir().expect("tempdir");
        let (source, bundle) = (root.path().join("source"), root.path().join("bundle"));
        backfilled_source(&fixture, &source);
        exported_bundle(&fixture, &source, &bundle);
        let base = fixture.tip_watermark();
        let exported = bundle.join(ARTIFACT);
        let size = fs::metadata(&exported)
            .expect("exported artifact metadata")
            .len();
        let decoded = size.saturating_sub(73);
        let headers = chain_headers(&fixture, base.height, base.hash);
        let header_refs: Vec<&[u8; 80]> = headers.iter().collect();

        let attach = root.path().join("attach");
        fs::create_dir_all(&attach).expect("attach dir");
        fs::copy(&exported, attach.join(ARTIFACT)).expect("stage manifest artifact");
        let budget = SpillBudget::new(1024);
        let receiver = open_receiver(root.path(), "receiver-bounded");
        let records = attach_tx_lookup_artifact(
            receiver.writer(),
            &manifest_target(
                &attach.join(ARTIFACT),
                base,
                digest_of(&attach.join(ARTIFACT)),
                size,
                fixture.txs_through(base.height),
            ),
            &header_refs,
            &attach,
            &budget,
        )
        .expect("a bounded re-encode attaches");
        assert!(records > 0, "the attached artifact produced no rows");
        assert!(
            budget.peak_bytes() > 0,
            "the re-encode must charge the spill budget or the bound is vacuous"
        );
        assert!(
            decoded > budget.peak_bytes(),
            "the artifact must exceed the budget to prove streaming: {decoded} <= {}",
            budget.peak_bytes()
        );
        assert!(
            budget.peak_bytes() <= 1024,
            "the re-encode buffered {} bytes above the 1024-byte budget",
            budget.peak_bytes()
        );
        drop(receiver);
        assert_eq!(
            durable(&root.path().join("receiver-bounded")),
            durable(&source),
            "the bounded restore serves the backfilled rows"
        );
    }

    #[test]
    fn export_preserves_a_preexisting_destination() {
        let fixture = ChainFixture::new(4, 20);
        let root = tempfile::tempdir().expect("tempdir");
        let source = root.path().join("source");
        let source_state = backfilled_source(&fixture, &source);

        let with_manifest = root.path().join("has-manifest");
        fs::create_dir_all(&with_manifest).expect("create destination");
        fs::write(with_manifest.join(MANIFEST), b"operator manifest").expect("seed manifest");
        fs::write(with_manifest.join("notes.txt"), b"operator notes").expect("seed notes");

        let with_artifact = root.path().join("has-artifact");
        fs::create_dir_all(&with_artifact).expect("create destination");
        fs::write(with_artifact.join(ARTIFACT), b"operator artifact").expect("seed artifact");

        for destination in [&with_manifest, &with_artifact] {
            let before = read_dir_files(destination);
            let node = Node::start(
                &fixture,
                &source,
                Start {
                    bundle: export(destination),
                    backfill: true,
                    ..Start::default()
                },
            );
            node.wait_reconciling();
            node.stop();
            assert_eq!(
                read_dir_files(destination),
                before,
                "export touched preexisting files in {}",
                destination.display()
            );
        }
        assert_eq!(durable(&source), source_state);

        let fresh = root.path().join("fresh");
        exported_bundle(&fixture, &source, &fresh);
    }

    #[test]
    fn cancelled_export_removes_only_its_own_staging() {
        let fixture = ChainFixture::new(3, 2 * CANCEL_POLL_RECORDS / 3 + 1);
        assert!(fixture.txids.len() > CANCEL_POLL_RECORDS);
        let root = tempfile::tempdir().expect("tempdir");
        let (source, bundle) = (root.path().join("source"), root.path().join("bundle"));
        let source_state = backfilled_source(&fixture, &source);
        fs::create_dir_all(&bundle).expect("create destination");
        fs::write(bundle.join("notes.txt"), b"operator notes").expect("seed notes");
        let before = read_dir_files(&bundle);
        let staged = Arc::new(AtomicBool::new(false));

        let node = Node::start(
            &fixture,
            &source,
            Start {
                bundle: export(&bundle),
                backfill: true,
                cancel_on_body_read: true,
                witness: Some((bundle.join(ARTIFACT), Arc::clone(&staged))),
                ..Start::default()
            },
        );
        node.wait_finished();
        node.stop();
        assert!(
            staged.load(Ordering::Acquire),
            "export was cancelled before it created its artifact"
        );
        assert_eq!(
            read_dir_files(&bundle),
            before,
            "cancelled export left staging"
        );
        assert_eq!(durable(&source), source_state);

        exported_bundle(&fixture, &source, &bundle);
        assert_eq!(
            fs::read(bundle.join("notes.txt")).expect("operator notes"),
            b"operator notes"
        );
    }

    #[test]
    fn cancelled_restore_writes_nothing_and_restart_completes() {
        let fixture = ChainFixture::new(3, 2 * CANCEL_POLL_RECORDS / 3 + 1);
        let root = tempfile::tempdir().expect("tempdir");
        let (source, receiver, bundle) = (
            root.path().join("source"),
            root.path().join("receiver"),
            root.path().join("bundle"),
        );
        let source_state = backfilled_source(&fixture, &source);
        exported_bundle(&fixture, &source, &bundle);

        let node = Node::start(
            &fixture,
            &receiver,
            Start {
                bundle: restore(&bundle),
                cancel_on_body_read: true,
                ..Start::default()
            },
        );
        node.wait_finished();
        node.stop();
        assert_untouched_fresh(&receiver);

        let node = Node::start(
            &fixture,
            &receiver,
            Start {
                bundle: restore(&bundle),
                ..Start::default()
            },
        );
        node.wait_synced(fixture.tip.height);
        node.stop();
        assert_eq!(durable(&receiver), source_state);
    }

    #[test]
    fn missing_bodies_withhold_readiness_until_ordinary_backfill() {
        let fixture = ChainFixture::new(5, 25);
        let root = tempfile::tempdir().expect("tempdir");
        let (source, bundle) = (root.path().join("source"), root.path().join("bundle"));
        let source_state = backfilled_source(&fixture, &source);
        exported_bundle(&fixture, &source, &bundle);
        let (probe_txid, _) = fixture.txids[1];

        for (name, bodies) in [
            ("hidden-body", Bodies::Hidden(3)),
            ("no-body-source", Bodies::NoSource),
        ] {
            let receiver = root.path().join(format!("receiver-{name}"));
            let node = Node::start(
                &fixture,
                &receiver,
                Start {
                    bundle: restore(&bundle),
                    bodies,
                    ..Start::default()
                },
            );
            node.wait_reconciling();
            assert!(
                !node.synced_at(fixture.tip.height),
                "{name}: withheld bundle made the index ready"
            );
            assert!(
                !matches!(node.adapter.transaction_block(&probe_txid), Ok(Some(_))),
                "{name}: withheld bundle served a lookup"
            );
            node.stop();
            assert_untouched_fresh(&receiver);

            let node = Node::start(
                &fixture,
                &receiver,
                Start {
                    backfill: true,
                    ..Start::default()
                },
            );
            node.wait_synced(fixture.tip.height);
            node.stop();
            assert_eq!(durable(&receiver), source_state, "{name}: backfill differs");
        }
    }

    #[test]
    fn interrupted_import_is_cleared_on_restart_and_restore_retries() {
        let blocks = 24_u32;
        let per_block = IMPORT_BATCH_ROWS / 24 + 200;
        let fixture = ChainFixture::new(blocks, per_block);
        assert!(fixture.txids.len() > IMPORT_BATCH_ROWS);
        let root = tempfile::tempdir().expect("tempdir");
        let (source, receiver, bundle) = (
            root.path().join("source"),
            root.path().join("receiver"),
            root.path().join("bundle"),
        );
        let source_state = backfilled_source(&fixture, &source);
        exported_bundle(&fixture, &source, &bundle);

        let node = Node::start(
            &fixture,
            &receiver,
            Start {
                bundle: restore(&bundle),
                crash_after_bulk_import: true,
                ..Start::default()
            },
        );
        node.wait_finished();
        assert!(
            node.failure().is_some(),
            "an import that cannot commit must fail the worker"
        );
        node.stop();
        let interrupted = durable(&receiver);
        assert_eq!(
            interrupted.tx_confirmed.len(),
            source_state.tx_confirmed.len(),
            "the injected crash must leave the full unwatermarked bulk import on disk"
        );
        let source_rows: HashSet<_> = source_state.tx_confirmed.iter().collect();
        assert!(
            interrupted
                .tx_confirmed
                .iter()
                .all(|row| source_rows.contains(row)),
            "partial import rows must be bundle rows"
        );
        assert_eq!(interrupted.watermark, None, "partial import became ready");

        let node = Node::start(&fixture, &receiver, Start::default());
        node.wait_reconciling();
        assert!(!node.synced_at(fixture.tip.height));
        node.stop();
        assert_untouched_fresh(&receiver);

        let node = Node::start(
            &fixture,
            &receiver,
            Start {
                bundle: restore(&bundle),
                ..Start::default()
            },
        );
        node.wait_synced(fixture.tip.height);
        node.stop();
        assert_eq!(durable(&receiver), source_state);
    }
}
mod query_answers {
    use bitcoin_rs_projection::segment::bulk_builder::BulkSegmentBuilder;
    use bitcoin_rs_projection::{IndexReader, Indexer, ScriptHash};
    use bitcoin_rs_storage::budget::UnboundedBudget;
    use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, TxFacts};
    use bitcoin_rs_storage::{FactsScript, PrefixScanLimit, RocksDbStore};
    use std::sync::Arc;
    use tempfile::tempdir;

    use crate::support::TestError;

    // PRJ-07
    #[test]
    fn no_segment_offset_in_answers() -> Result<(), TestError> {
        use bitcoin_rs_projection::types::ScriptHistoryOccurrence;

        let gen_id = 1u64;
        let dir = tempdir()?;
        let scratch = tempdir()?;
        let store = RocksDbStore::open(dir.path())?;

        let block_hash = [0x55u8; 32];
        let txid = [0x42u8; 32];
        let height = 100u32;
        let script = FactsScript::copy_from_slice(b"\x76\xa9\x14query_ans_script\x88\xac");

        let block = CommittedBlock {
            height,
            hash: block_hash,
            parent_hash: [0u8; 32],
            header: [0u8; 80],
            txs: vec![TxFacts {
                txid,
                offset: 450,
                len: 220,
                inputs: Vec::new(),
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: 50_000,
                    script: script.clone(),
                }],
            }],
        };

        let builder = BulkSegmentBuilder::new(
            Arc::new(UnboundedBudget),
            None,
            scratch.path().to_path_buf(),
        );
        let coverage = builder
            .build_and_ingest(&store, gen_id, &[block])
            .map_err(|e| e.to_string())?;
        bitcoin_rs_projection::segment::publish_bulk_generation(
            &store,
            gen_id,
            coverage,
            1,
            bitcoin_rs_projection::IndexCapabilities::ALL,
        )?;

        let scripthash = ScriptHash::from_script_bytes(script.as_ref());
        let store = Arc::new(store);
        let indexer = Indexer::new(Arc::clone(&store));
        let view = indexer.snapshot()?;
        let limit = PrefixScanLimit {
            max_rows: 100,
            max_bytes: usize::MAX,
        };
        let funding = view.funding_rows(scripthash, limit)?;
        assert_eq!(funding.rows.len(), 1, "one funding row answers the script");
        assert_eq!(funding.rows[0].row.height(), 100);
        assert_eq!(
            funding.rows[0].row.prefix,
            scripthash.prefix(),
            "the answer key is the logical script prefix and height"
        );
        let occurrences = ScriptHistoryOccurrence::decode_all(&funding.rows[0].value)
            .ok_or("decode funding answer")?;
        assert_eq!(occurrences.len(), 1);
        assert_eq!(
            occurrences[0].txid, txid,
            "the answer names the logical txid"
        );
        assert_eq!(
            occurrences[0].flags,
            ScriptHistoryOccurrence::FUNDING,
            "the answer flags the funding occurrence"
        );
        Ok(())
    }
}
mod reorg_retirement {
    use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid};
    use bitcoin_rs_projection::IndexCapability;
    use bitcoin_rs_projection::segment::bulk_builder::BulkSegmentBuilder;
    use bitcoin_rs_projection::segment::{
        Coverage, IndexGeneration, meta_gen_key, publish_sealed, retire_generation, sealed_gen_key,
    };
    use bitcoin_rs_projection::types::{ScriptHash, ScriptHistoryOccurrence, TxPositionValue};
    use bitcoin_rs_projection::{IndexCapabilities, IndexReader, Indexer};
    use bitcoin_rs_storage::budget::UnboundedBudget;
    use bitcoin_rs_storage::committed_facts::{
        CommittedBlock, CreatedOutput, SpentPrevout, TxFacts,
    };
    use bitcoin_rs_storage::{ColumnFamily, FactsScript, KvStore, PrefixScanLimit, RocksDbStore};
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

        let script = FactsScript::copy_from_slice(b"\x76\xa9\x14retire_script\x88\xac");
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
}
mod script_history_artifact {
    #![expect(
        clippy::expect_used,
        reason = "test: fixture setup failures abort the test with context"
    )]

    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::{Hash as _, sha256};
    use bitcoin::hex::FromHex as _;
    use bitcoin_rs_consensus::primitives::Network;
    use bitcoin_rs_projection::portable::{
        IndexBundleError, ManifestArtifactTarget, ScriptHistoryArtifact, SpillBudget,
        attach_script_history_artifact, write_script_history_artifact,
    };
    use bitcoin_rs_projection::types::ScriptHistoryOccurrence;
    use bitcoin_rs_projection::{
        IndexCapabilities, IndexCapability, IndexError, IndexReader, IndexWatermark, IndexWriter,
        Indexer, PreparedBatch, PreparedBatchLimits, ScriptHash, SpentCoin, SpentCoins,
        TxIndexSnapshot, index_format_version,
    };
    use bitcoin_rs_storage::{ColumnFamily, KvStore, PrefixScanLimit};
    use parking_lot::RwLock;

    use crate::support::{TestError, common::MemoryStore};

    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/storage/fixtures/core-v2/blocks200.json"
    );
    const SCAN_ALL: PrefixScanLimit = PrefixScanLimit {
        max_rows: 1_000_000,
        max_bytes: 256 << 20,
    };
    const FUNDING: u8 = ScriptHistoryOccurrence::FUNDING;

    type Occurrence = (u32, [u8; 32], u8);

    struct NoSpent;

    impl SpentCoins for NoSpent {
        fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
            None
        }
    }

    struct Fixture {
        raw: Vec<Vec<u8>>,
        blocks: Vec<bitcoin::Block>,
        hashes: Vec<[u8; 32]>,
    }

    fn load_fixture() -> Fixture {
        let text = fs::read_to_string(FIXTURE).expect("core-v2 block fixture");
        let hexes: Vec<String> =
            sonic_rs::from_str(&text).expect("block fixture is a JSON array of hex strings");
        let raw: Vec<Vec<u8>> = hexes
            .iter()
            .map(|hex| Vec::<u8>::from_hex(hex).expect("fixture block is hex"))
            .collect();
        let blocks: Vec<bitcoin::Block> = raw
            .iter()
            .map(|bytes| deserialize(bytes).expect("fixture block decodes"))
            .collect();
        for pair in blocks.windows(2) {
            assert_eq!(
                pair[1].header.prev_blockhash,
                pair[0].block_hash(),
                "fixture blocks form one chain in list order"
            );
        }
        let hashes = blocks
            .iter()
            .map(|block| block.block_hash().to_byte_array())
            .collect();
        Fixture {
            raw,
            blocks,
            hashes,
        }
    }

    fn height_of(index: usize) -> u32 {
        u32::try_from(index).expect("fixture height fits in u32")
    }

    fn funded_scripthashes(fixture: &Fixture) -> Vec<[u8; 32]> {
        let mut hashes = BTreeSet::new();
        for block in &fixture.blocks {
            for tx in &block.txdata {
                for output in &tx.output {
                    if !output.script_pubkey.is_op_return() {
                        let hash = sha256::Hash::hash(output.script_pubkey.as_bytes());
                        hashes.insert(hash.to_byte_array());
                    }
                }
            }
        }
        hashes.into_iter().collect()
    }

    fn pays_scripthash(tx: &bitcoin::Transaction, scripthash: [u8; 32]) -> bool {
        tx.output.iter().any(|output| {
            !output.script_pubkey.is_op_return()
                && sha256::Hash::hash(output.script_pubkey.as_bytes()).to_byte_array() == scripthash
        })
    }

    fn expected_funding(fixture: &Fixture, scripthash: [u8; 32]) -> Vec<Occurrence> {
        let mut found = Vec::new();
        for (index, block) in fixture.blocks.iter().enumerate() {
            for tx in &block.txdata {
                if pays_scripthash(tx, scripthash) {
                    let txid = tx.compute_txid().to_byte_array();
                    found.push((height_of(index), txid, FUNDING));
                }
            }
        }
        found.sort_unstable();
        found
    }

    fn served_funding(snapshot: &dyn TxIndexSnapshot, scripthash: [u8; 32]) -> Vec<Occurrence> {
        let scan = snapshot
            .funding_rows(ScriptHash::from_byte_array(scripthash), SCAN_ALL)
            .expect("funding rows at the base");
        assert!(scan.complete, "one bounded scan covers the script");
        let mut found = Vec::new();
        for row in scan.rows {
            let height = row.row.height();
            let occurrences = ScriptHistoryOccurrence::decode_all(&row.value).expect("valid row");
            for occurrence in occurrences {
                if occurrence.scripthash.to_byte_array() == scripthash {
                    found.push((height, occurrence.txid, occurrence.flags));
                }
            }
        }
        found.sort_unstable();
        found
    }

    fn build_source(fixture: &Fixture) -> (Arc<MemoryStore>, IndexWriter<MemoryStore>) {
        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1).expect("source writer");
        for (index, body) in fixture.raw.iter().enumerate() {
            let prepared = writer
                .prepare_block_with_spent_scripts(
                    IndexCapabilities::HISTORICAL,
                    height_of(index),
                    fixture.hashes[index],
                    body,
                    &NoSpent,
                )
                .expect("fixture block prepares");
            let mut batch = PreparedBatch::new(PreparedBatchLimits {
                max_rows: usize::MAX,
                max_bytes: usize::MAX,
            });
            assert!(batch.try_push(prepared).is_ok(), "one block per batch");
            writer.commit_forward(batch).expect("fixture block commits");
        }
        (store, writer)
    }

    fn produce(
        source: &IndexWriter<MemoryStore>,
        network: Network,
        dir: &Path,
        name: &str,
    ) -> (PathBuf, ScriptHistoryArtifact) {
        let path = dir.join(name);
        let artifact = write_script_history_artifact(source, network, &path)
            .expect("producer writes the artifact");
        (path, artifact)
    }

    fn chain_tx_count(fixture: &Fixture) -> Result<u64, TestError> {
        let mut total = 0u64;
        for block in &fixture.blocks {
            total += u64::try_from(block.txdata.len())?;
        }
        Ok(total)
    }

    fn target(
        artifact: &Path,
        base: IndexWatermark,
        sha256: [u8; 32],
        size_bytes: u64,
        chain_tx_count: u64,
    ) -> ManifestArtifactTarget {
        ManifestArtifactTarget {
            artifact_path: artifact.to_path_buf(),
            base_height: base.height,
            base_hash: base.hash,
            floor: 0,
            network: Network::Regtest,
            index_format: index_format_version(),
            sha256,
            size_bytes,
            chain_tx_count,
        }
    }

    fn empty_receiver() -> (Arc<MemoryStore>, RwLock<IndexWriter<MemoryStore>>) {
        let store = Arc::new(MemoryStore::default());
        let writer = IndexWriter::open(Arc::clone(&store), 1).expect("receiver writer");
        (store, RwLock::new(writer))
    }

    fn rows_of(store: &MemoryStore, cf: ColumnFamily) -> Vec<(Vec<u8>, Vec<u8>)> {
        store
            .iter_prefix(cf, &[])
            .expect("family scan")
            .collect::<Result<Vec<_>, _>>()
            .expect("family rows")
    }

    fn assert_untouched(store: &Arc<MemoryStore>) {
        let indexer = Indexer::new(Arc::clone(store));
        let snapshot = indexer.snapshot().expect("receiver snapshot");
        assert_eq!(
            snapshot
                .capability_watermark(IndexCapability::ScriptHistory)
                .expect("watermark read"),
            None,
            "a refused artifact publishes no watermark"
        );
        assert!(
            rows_of(store, ColumnFamily::Funding).is_empty(),
            "a refused artifact writes no Funding rows"
        );
        assert!(
            rows_of(store, ColumnFamily::Spending).is_empty(),
            "a refused artifact writes no Spending rows"
        );
    }

    fn base_at_tip(fixture: &Fixture) -> IndexWatermark {
        let last = fixture.blocks.len() - 1;
        IndexWatermark {
            height: height_of(last),
            hash: fixture.hashes[last],
        }
    }

    // SNP-05
    #[test]
    fn good_artifact_attaches_and_serves_the_live_rows_at_its_base() -> Result<(), TestError> {
        let fixture = load_fixture();
        let (source_store, source) = build_source(&fixture);
        let root = tempfile::tempdir().expect("tempdir");
        let (path, artifact) = produce(&source, Network::Regtest, root.path(), "good.dat");
        let base = base_at_tip(&fixture);
        assert_eq!(artifact.base, base, "the artifact is cut at the live base");

        let (receiver_store, receiver) = empty_receiver();
        let attached = attach_script_history_artifact(
            &receiver,
            &target(
                &path,
                base,
                artifact.sha256,
                artifact.bytes,
                chain_tx_count(&fixture)?,
            ),
            &fixture.hashes,
            root.path(),
            &SpillBudget::new(u64::MAX),
        )
        .expect("a verified artifact attaches");
        assert_eq!(
            attached, artifact.records,
            "every artifact record is ingested"
        );
        assert!(attached > 0, "the fixture produces history rows");

        let indexer = Indexer::new(Arc::clone(&receiver_store));
        let snapshot = indexer.snapshot().expect("receiver snapshot");
        assert_eq!(
            snapshot
                .capability_watermark(IndexCapability::ScriptHistory)
                .expect("watermark read"),
            Some(base),
            "the attach publishes the manifest base as coverage"
        );
        assert_eq!(
            snapshot
                .capability_floor(IndexCapability::ScriptHistory)
                .expect("floor read"),
            0,
            "the attach publishes the manifest floor"
        );
        for scripthash in funded_scripthashes(&fixture) {
            let expected = expected_funding(&fixture, scripthash);
            assert!(!expected.is_empty(), "every listed script is funded");
            assert_eq!(
                served_funding(snapshot.as_ref(), scripthash),
                expected,
                "the served history equals the fixture's funding rows"
            );
        }
        assert_eq!(
            rows_of(&receiver_store, ColumnFamily::Funding),
            rows_of(&source_store, ColumnFamily::Funding),
            "attached Funding rows equal the live rows"
        );
        assert_eq!(
            rows_of(&receiver_store, ColumnFamily::Spending),
            rows_of(&source_store, ColumnFamily::Spending),
            "attached Spending rows equal the live rows"
        );
        Ok(())
    }

    // SNP-03
    #[test]
    fn forged_digest_is_refused_without_rows_or_watermark() -> Result<(), TestError> {
        let fixture = load_fixture();
        let (_source_store, source) = build_source(&fixture);
        let root = tempfile::tempdir().expect("tempdir");
        let (path, artifact) = produce(&source, Network::Regtest, root.path(), "forged.dat");
        let mut forged = artifact.sha256;
        forged[0] ^= 0x01;

        let (receiver_store, receiver) = empty_receiver();
        let error = attach_script_history_artifact(
            &receiver,
            &target(
                &path,
                base_at_tip(&fixture),
                forged,
                artifact.bytes,
                chain_tx_count(&fixture)?,
            ),
            &fixture.hashes,
            root.path(),
            &SpillBudget::new(u64::MAX),
        )
        .expect_err("an artifact with a forged digest must be refused");
        assert!(
            matches!(error, IndexBundleError::ArtifactHash { .. }),
            "got {error:?}"
        );
        assert_untouched(&receiver_store);
        Ok(())
    }

    // SNP-03
    #[test]
    fn foreign_base_hash_is_refused_without_rows_or_watermark() -> Result<(), TestError> {
        let fixture = load_fixture();
        let (_source_store, source) = build_source(&fixture);
        let root = tempfile::tempdir().expect("tempdir");
        let (path, artifact) = produce(&source, Network::Regtest, root.path(), "base.dat");
        let mut foreign = base_at_tip(&fixture);
        foreign.hash[0] ^= 0x01;

        let (receiver_store, receiver) = empty_receiver();
        let error = attach_script_history_artifact(
            &receiver,
            &target(
                &path,
                foreign,
                artifact.sha256,
                artifact.bytes,
                chain_tx_count(&fixture)?,
            ),
            &fixture.hashes,
            root.path(),
            &SpillBudget::new(u64::MAX),
        )
        .expect_err("an artifact cut at another base must be refused");
        assert!(
            matches!(error, IndexBundleError::ArtifactHeader { .. }),
            "got {error:?}"
        );
        assert_untouched(&receiver_store);
        Ok(())
    }

    // SNP-03
    #[test]
    fn foreign_network_magic_is_refused_without_rows_or_watermark() -> Result<(), TestError> {
        let fixture = load_fixture();
        let (_source_store, source) = build_source(&fixture);
        let root = tempfile::tempdir().expect("tempdir");
        let (path, artifact) = produce(&source, Network::Signet, root.path(), "signet.dat");

        let (receiver_store, receiver) = empty_receiver();
        let error = attach_script_history_artifact(
            &receiver,
            &target(
                &path,
                base_at_tip(&fixture),
                artifact.sha256,
                artifact.bytes,
                chain_tx_count(&fixture)?,
            ),
            &fixture.hashes,
            root.path(),
            &SpillBudget::new(u64::MAX),
        )
        .expect_err("an artifact cut on another network must be refused");
        assert!(
            matches!(error, IndexBundleError::ArtifactHeader { .. }),
            "got {error:?}"
        );
        assert_untouched(&receiver_store);
        Ok(())
    }

    // SNP-03
    #[test]
    fn truncated_payload_is_refused_without_rows_or_watermark() -> Result<(), TestError> {
        let fixture = load_fixture();
        let (_source_store, source) = build_source(&fixture);
        let root = tempfile::tempdir().expect("tempdir");
        let (path, artifact) = produce(&source, Network::Regtest, root.path(), "full.dat");
        let bytes = fs::read(&path).expect("artifact bytes");
        let short = root.path().join("short.dat");
        fs::write(&short, &bytes[..bytes.len() - 5]).expect("truncated artifact");
        let short_bytes = fs::read(&short).expect("truncated bytes");
        let short_digest = sha256::Hash::hash(&short_bytes).to_byte_array();
        let base = base_at_tip(&fixture);

        let (receiver_store, receiver) = empty_receiver();
        let error = attach_script_history_artifact(
            &receiver,
            &target(
                &short,
                base,
                short_digest,
                u64::try_from(short_bytes.len()).expect("length fits"),
                chain_tx_count(&fixture)?,
            ),
            &fixture.hashes,
            root.path(),
            &SpillBudget::new(u64::MAX),
        )
        .expect_err("a manifest matching a truncated payload must be refused");
        assert!(
            matches!(error, IndexBundleError::ArtifactHeader { .. }),
            "the header payload length must match the bytes: {error:?}"
        );

        let error = attach_script_history_artifact(
            &receiver,
            &target(
                &short,
                base,
                artifact.sha256,
                artifact.bytes,
                chain_tx_count(&fixture)?,
            ),
            &fixture.hashes,
            root.path(),
            &SpillBudget::new(u64::MAX),
        )
        .expect_err("a manifest declaring the full length must refuse the short file");
        assert!(
            matches!(error, IndexBundleError::ArtifactLength { .. }),
            "got {error:?}"
        );
        assert_untouched(&receiver_store);
        Ok(())
    }

    #[test]
    fn second_attach_over_a_populated_family_is_refused() -> Result<(), TestError> {
        let fixture = load_fixture();
        let (_source_store, source) = build_source(&fixture);
        let root = tempfile::tempdir().expect("tempdir");
        let (path, artifact) = produce(&source, Network::Regtest, root.path(), "twice.dat");
        let base = base_at_tip(&fixture);
        let manifest = target(
            &path,
            base,
            artifact.sha256,
            artifact.bytes,
            chain_tx_count(&fixture)?,
        );

        let (receiver_store, receiver) = empty_receiver();
        attach_script_history_artifact(
            &receiver,
            &manifest,
            &fixture.hashes,
            root.path(),
            &SpillBudget::new(u64::MAX),
        )
        .map_err(|e| e.to_string())?;
        let before = rows_of(&receiver_store, ColumnFamily::Funding);

        let error = attach_script_history_artifact(
            &receiver,
            &manifest,
            &fixture.hashes,
            root.path(),
            &SpillBudget::new(u64::MAX),
        )
        .expect_err("a populated ScriptHistory family must refuse a second attach");
        assert!(
            matches!(
                error,
                IndexBundleError::Index(IndexError::WatermarkMismatch { .. })
            ),
            "got {error:?}"
        );
        assert_eq!(
            rows_of(&receiver_store, ColumnFamily::Funding),
            before,
            "the refused attach leaves the attached rows unchanged"
        );
        Ok(())
    }

    #[test]
    fn populated_rows_without_a_watermark_are_refused_and_kept() -> Result<(), TestError> {
        let fixture = load_fixture();
        let (_source_store, source) = build_source(&fixture);
        let root = tempfile::tempdir().expect("tempdir");
        let (path, artifact) = produce(&source, Network::Regtest, root.path(), "stray.dat");

        let (receiver_store, receiver) = empty_receiver();
        let stray_key = [0xEE_u8; 12];
        let stray_value = vec![0xEE_u8; ScriptHistoryOccurrence::SIZE];
        receiver_store
            .put(ColumnFamily::Funding, &stray_key, &stray_value)
            .expect("stray row is staged");
        let error = attach_script_history_artifact(
            &receiver,
            &target(
                &path,
                base_at_tip(&fixture),
                artifact.sha256,
                artifact.bytes,
                chain_tx_count(&fixture)?,
            ),
            &fixture.hashes,
            root.path(),
            &SpillBudget::new(u64::MAX),
        )
        .expect_err("a family that already holds rows must refuse the attach");
        assert!(
            matches!(
                error,
                IndexBundleError::Index(IndexError::ScriptHistoryPopulated)
            ),
            "got {error:?}"
        );
        assert_eq!(
            rows_of(&receiver_store, ColumnFamily::Funding),
            vec![(stray_key.to_vec(), stray_value)],
            "the refused attach keeps the rows it found"
        );
        Ok(())
    }
}
mod script_history_occurrences {
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::support::{TestError, common::MemoryStore};
    use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid, encode};
    use bitcoin_rs_projection::segment::bulk_builder::BulkSegmentBuilder;
    use bitcoin_rs_projection::segment::publish_sealed;
    use bitcoin_rs_projection::types::ScriptHistoryOccurrence;
    use bitcoin_rs_projection::{
        IndexCapabilities, IndexError, IndexReader, IndexWatermark, IndexWriter, Indexer,
        PreparedBatch, PreparedBatchLimits, ScriptHash, SpentCoin, SpentCoins, TxIndexScanRow,
    };
    use bitcoin_rs_storage::budget::UnboundedBudget;
    use bitcoin_rs_storage::committed_facts::{
        CommittedBlock, CreatedOutput, SpentPrevout, TxFacts,
    };
    use bitcoin_rs_storage::{ColumnFamily, FactsScript, KvStore, PrefixScanLimit, RocksDbStore};

    const BLOCKS: u32 = 12;

    const SCAN_ALL: PrefixScanLimit = PrefixScanLimit {
        max_rows: 100_000,
        max_bytes: 64 << 20,
    };

    fn script_for(seed: u32) -> Vec<u8> {
        let mut script = Vec::with_capacity(22);
        script.push(0x00);
        script.push(0x14);
        script.extend_from_slice(&[0x11; 20]);
        script[2] = u8::try_from(seed % 251).unwrap_or(0);
        script[3] = u8::try_from((seed / 251) % 251).unwrap_or(0);
        script
    }

    #[derive(Default)]
    struct ChainScripts {
        by_txid: HashMap<[u8; 32], Vec<u8>>,
    }

    impl SpentCoins for ChainScripts {
        fn spent_coin(&self, txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
            self.by_txid.get(txid).map(|script| SpentCoin {
                script,
                value: 0,
                height: 0,
                coinbase: false,
            })
        }
    }

    struct Chain {
        blocks: Vec<Vec<u8>>,
        hashes: Vec<Hash256>,
        coinbase_txids: Vec<[u8; 32]>,
        spend_txids: Vec<[u8; 32]>,
        scripts: ChainScripts,
    }

    fn push_tx(body: &mut Vec<u8>, tx: &[u8]) {
        body.extend_from_slice(tx);
    }

    fn build_chain() -> Chain {
        let capacity = usize::try_from(BLOCKS).unwrap_or(0);
        let mut blocks = Vec::with_capacity(capacity);
        let mut hashes = Vec::with_capacity(capacity);
        let mut coinbase_txids = Vec::with_capacity(capacity);
        let mut spend_txids = Vec::with_capacity(capacity);
        let mut scripts = ChainScripts::default();
        let mut previous = Hash256::from_le_bytes(&[0; 32]);

        for height in 0..BLOCKS {
            let coinbase_script = script_for(height);
            let mut coinbase = Vec::new();
            coinbase.extend_from_slice(&1_u32.to_le_bytes());
            coinbase.push(0x01);
            coinbase.extend_from_slice(&[0_u8; 32]);
            coinbase.extend_from_slice(&u32::MAX.to_le_bytes());
            coinbase.push(0x02);
            coinbase.extend_from_slice(&[u8::try_from(height % 251).unwrap_or(0), 0xFF]);
            coinbase.extend_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
            coinbase.push(0x01);
            coinbase.extend_from_slice(&500_000_000_u64.to_le_bytes());
            coinbase.push(u8::try_from(coinbase_script.len()).unwrap_or(0));
            coinbase.extend_from_slice(&coinbase_script);
            coinbase.extend_from_slice(&0_u32.to_le_bytes());
            let coinbase_txid = encode::double_sha256(&coinbase);
            coinbase_txids.push(coinbase_txid.to_le_bytes());
            scripts
                .by_txid
                .insert(coinbase_txid.to_le_bytes(), coinbase_script.clone());

            let mut spend = Vec::new();
            if height > 0 {
                let spend_script = script_for(1_000 + height);
                spend.extend_from_slice(&1_u32.to_le_bytes());
                spend.push(0x01);
                spend.extend_from_slice(
                    &coinbase_txids[usize::try_from(height.saturating_sub(1)).unwrap_or(0)],
                );
                spend.extend_from_slice(&0_u32.to_le_bytes());
                spend.push(0x00);
                spend.extend_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
                spend.push(0x01);
                spend.extend_from_slice(&1_000_u64.to_le_bytes());
                spend.push(u8::try_from(spend_script.len()).unwrap_or(0));
                spend.extend_from_slice(&spend_script);
                spend.extend_from_slice(&0_u32.to_le_bytes());
                spend_txids.push(encode::double_sha256(&spend).to_le_bytes());
            }

            let mut body = Vec::new();
            body.extend_from_slice(&1_i32.to_le_bytes());
            body.extend_from_slice(&previous.to_le_bytes());
            body.extend_from_slice(&[0_u8; 32]);
            body.extend_from_slice(&(1_600_000_000_u32.saturating_add(height)).to_le_bytes());
            body.extend_from_slice(&0x207F_FFFF_u32.to_le_bytes());
            body.extend_from_slice(&0_u32.to_le_bytes());
            body.push(u8::try_from(1 + usize::from(height > 0)).unwrap_or(0));
            push_tx(&mut body, &coinbase);
            if height > 0 {
                push_tx(&mut body, &spend);
            }
            let hash = encode::double_sha256(&body[..80]);
            blocks.push(body);
            hashes.push(hash);
            previous = hash;
        }

        Chain {
            blocks,
            hashes,
            coinbase_txids,
            spend_txids,
            scripts,
        }
    }

    fn commit_chain<S>(
        writer: &mut IndexWriter<S>,
        chain: &Chain,
    ) -> Result<Vec<IndexWatermark>, IndexError>
    where
        S: KvStore + 'static,
    {
        let mut watermarks = Vec::with_capacity(chain.blocks.len());
        for (height, body) in chain.blocks.iter().enumerate() {
            let Some(hash) = chain.hashes.get(height) else {
                return Err(IndexError::NonContiguousPrepared { watermark: None });
            };
            let prepared = writer.prepare_block_with_spent_scripts(
                IndexCapabilities::HISTORICAL,
                u32::try_from(height).unwrap_or(0),
                hash.to_le_bytes(),
                body,
                &chain.scripts,
            )?;
            let mut batch = bitcoin_rs_projection::PreparedBatch::new(
                bitcoin_rs_projection::PreparedBatchLimits {
                    max_rows: usize::MAX,
                    max_bytes: usize::MAX,
                },
            );
            assert!(
                batch.try_push(prepared).is_ok(),
                "one block per batch is admitted"
            );
            watermarks.push(writer.commit_forward(batch)?);
        }
        Ok(watermarks)
    }

    fn occurred(
        rows: &[bitcoin_rs_projection::TxIndexScanRow],
        scripthash: ScriptHash,
    ) -> Vec<(u32, [u8; 32], u8)> {
        let mut found = Vec::new();
        for row in rows {
            let height = row.row.height();
            for occurrence in ScriptHistoryOccurrence::decode_all(&row.value).unwrap_or_default() {
                if occurrence.scripthash == scripthash {
                    found.push((height, occurrence.txid, occurrence.flags));
                }
            }
        }
        found.sort_unstable();
        found
    }

    // IDX-02, IDX-09
    #[test]
    fn writer_stores_one_occurrence_per_script_height_and_transaction() -> Result<(), TestError> {
        let chain = build_chain();
        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        commit_chain(&mut writer, &chain)?;

        let indexer = Indexer::new(Arc::clone(&store));
        let snapshot = indexer.snapshot()?;
        let script = ScriptHash::from_script_bytes(&script_for(0));
        let rows = snapshot.funding_rows_from(script, u32::MAX, SCAN_ALL)?;
        assert!(rows.complete, "one bounded scan covers the fixture");
        assert_eq!(
            occurred(&rows.rows, script),
            vec![
                (0, chain.coinbase_txids[0], ScriptHistoryOccurrence::FUNDING),
                (1, chain.spend_txids[0], ScriptHistoryOccurrence::SPENDING),
            ],
            "the coinbase funds at 0 and the block-1 spend is keyed by the same script"
        );

        let payment = ScriptHash::from_script_bytes(&script_for(1_001));
        let rows = snapshot.funding_rows_from(payment, u32::MAX, SCAN_ALL)?;
        let occurrences = occurred(&rows.rows, payment);
        assert_eq!(occurrences.len(), 1, "the payment is funded once");
        assert_eq!(
            occurrences[0].0, 1,
            "the occurrence keeps its confirming height"
        );
        Ok(())
    }

    // IDX-06
    #[test]
    fn rollback_removes_exactly_the_disconnected_block_rows() -> Result<(), TestError> {
        let chain = build_chain();
        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let watermarks = commit_chain(&mut writer, &chain)?;
        let script = ScriptHash::from_script_bytes(&script_for(0));

        let last_arg = watermarks
            .iter()
            .rev()
            .nth(1)
            .copied()
            .ok_or("fixture needs at least two blocks")?;
        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            IndexCapabilities::HISTORICAL,
            Some(last_arg),
            chain
                .blocks
                .last()
                .ok_or("fixture needs at least one block")?,
            bitcoin_rs_projection::ConsumerCursorUpdate::Keep,
            &chain.scripts,
        )?;

        let indexer = Indexer::new(Arc::clone(&store));
        let snapshot = indexer.snapshot()?;
        let rows = snapshot.funding_rows_from(script, u32::MAX, SCAN_ALL)?;
        assert_eq!(
            occurred(&rows.rows, script),
            vec![
                (0, chain.coinbase_txids[0], ScriptHistoryOccurrence::FUNDING),
                (1, chain.spend_txids[0], ScriptHistoryOccurrence::SPENDING),
            ],
            "the disconnected spend no longer names the script"
        );
        assert_eq!(
            writer.watermark()?,
            watermarks.iter().rev().nth(1).copied(),
            "the watermark moves back one height"
        );
        Ok(())
    }

    // IDX-05, IDX-10
    #[test]
    fn reopen_serves_the_same_occurrence_rows() -> Result<(), TestError> {
        let chain = build_chain();
        let store = Arc::new(MemoryStore::default());
        let script = ScriptHash::from_script_bytes(&script_for(3));
        let before = {
            let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
            commit_chain(&mut writer, &chain)?;
            let indexer = Indexer::new(Arc::clone(&store));
            let snapshot = indexer.snapshot()?;
            occurred(
                &snapshot.funding_rows_from(script, u32::MAX, SCAN_ALL)?.rows,
                script,
            )
        };
        let writer = IndexWriter::open(Arc::clone(&store), 1)?;
        assert_eq!(
            writer.watermark()?,
            Some(IndexWatermark {
                height: BLOCKS - 1,
                hash: chain.hashes[chain.hashes.len() - 1].to_le_bytes(),
            }),
            "reopen keeps the committed watermark"
        );
        drop(writer);
        let indexer = Indexer::new(Arc::clone(&store));
        let snapshot = indexer.snapshot()?;
        let after = occurred(
            &snapshot.funding_rows_from(script, u32::MAX, SCAN_ALL)?.rows,
            script,
        );
        assert_eq!(after, before, "reopen serves identical occurrence rows");
        Ok(())
    }

    // IDX-05
    #[test]
    fn format_5_marker_refuses_and_rebuilds_the_derived_store() -> Result<(), TestError> {
        let chain = build_chain();
        let store = Arc::new(MemoryStore::default());
        store.put(
            ColumnFamily::UtxoMeta,
            &[0x00, b'V'],
            &[0x05, 0x00, 0x00, 0x00],
        )?;
        assert!(
            matches!(
                IndexWriter::open(Arc::clone(&store), 1),
                Err(IndexError::UnsupportedTxIndexFormatVersion { version: 5 })
            ),
            "a format-5 marker refuses open"
        );

        IndexWriter::reset_index(store.as_ref(), 1)?;
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        assert_eq!(writer.watermark()?, None, "reset leaves no watermark");
        commit_chain(&mut writer, &chain)?;
        let script = ScriptHash::from_script_bytes(&script_for(0));
        let indexer = Indexer::new(Arc::clone(&store));
        let snapshot = indexer.snapshot()?;
        assert_eq!(
            occurred(
                &snapshot.funding_rows_from(script, u32::MAX, SCAN_ALL)?.rows,
                script,
            )
            .len(),
            2,
            "the rebuilt store serves the same history"
        );
        Ok(())
    }

    // IDX-10
    #[test]
    fn failed_fenced_write_publishes_no_watermark_and_no_rows() -> Result<(), TestError> {
        let chain = build_chain();
        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let first = writer.prepare_block_with_spent_scripts(
            IndexCapabilities::HISTORICAL,
            0,
            chain.hashes[0].to_le_bytes(),
            &chain.blocks[0],
            &chain.scripts,
        )?;
        let mut batch =
            bitcoin_rs_projection::PreparedBatch::new(bitcoin_rs_projection::PreparedBatchLimits {
                max_rows: usize::MAX,
                max_bytes: usize::MAX,
            });
        assert!(batch.try_push(first).is_ok(), "first block is admitted");
        writer.commit_forward(batch)?;
        let committed_rows = store.count(ColumnFamily::TxDir);

        let second = writer.prepare_block_with_spent_scripts(
            IndexCapabilities::HISTORICAL,
            1,
            chain.hashes[1].to_le_bytes(),
            &chain.blocks[1],
            &chain.scripts,
        )?;
        let mut batch =
            bitcoin_rs_projection::PreparedBatch::new(bitcoin_rs_projection::PreparedBatchLimits {
                max_rows: usize::MAX,
                max_bytes: usize::MAX,
            });
        assert!(batch.try_push(second).is_ok(), "second block is admitted");
        store.arm_fenced_write_failure();
        assert!(
            writer.commit_forward(batch).is_err(),
            "the durability boundary reports the injected failure"
        );
        assert_eq!(
            writer.watermark()?,
            Some(IndexWatermark {
                height: 0,
                hash: chain.hashes[0].to_le_bytes(),
            }),
            "no newer watermark is published"
        );
        assert_eq!(
            store.count(ColumnFamily::TxDir),
            committed_rows,
            "no row of the failed batch is visible"
        );
        Ok(())
    }

    fn coinbase_txid(height: u32) -> [u8; 32] {
        let mut txid = [0xC0; 32];
        txid[..4].copy_from_slice(&height.to_be_bytes());
        txid
    }

    fn spend_txid(height: u32) -> [u8; 32] {
        let mut txid = [0x5E; 32];
        txid[..4].copy_from_slice(&height.to_be_bytes());
        txid
    }

    fn block_hash(height: u32) -> [u8; 32] {
        let mut hash = [0xB1; 32];
        hash[..4].copy_from_slice(&height.to_be_bytes());
        hash
    }

    fn facts_chain(blocks: u32) -> Vec<CommittedBlock> {
        let mut chain = Vec::with_capacity(usize::try_from(blocks).unwrap_or(0));
        for height in 0..blocks {
            let mut txs = vec![TxFacts {
                txid: coinbase_txid(height),
                offset: 81,
                len: 100,
                inputs: Vec::new(),
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: 50_0000_0000,
                    script: FactsScript::copy_from_slice(&script_for(height)),
                }],
            }];
            if height > 0 {
                txs.push(TxFacts {
                    txid: spend_txid(height),
                    offset: 181,
                    len: 150,
                    inputs: vec![SpentPrevout {
                        txid: coinbase_txid(height - 1),
                        vout: 0,
                        value: 50_0000_0000,
                        script: FactsScript::copy_from_slice(&script_for(height - 1)),
                        height: height - 1,
                        coinbase: true,
                    }],
                    outputs: vec![CreatedOutput {
                        vout: 0,
                        value: 49_0000_0000,
                        script: FactsScript::copy_from_slice(&script_for(height)),
                    }],
                });
            }
            chain.push(CommittedBlock {
                height,
                hash: block_hash(height),
                parent_hash: if height == 0 {
                    [0; 32]
                } else {
                    block_hash(height - 1)
                },
                header: [0; 80],
                txs,
            });
        }
        chain
    }

    fn segment_rows(rows: Vec<TxIndexScanRow>) -> Vec<(u32, Vec<u8>)> {
        let mut pairs: Vec<(u32, Vec<u8>)> = rows
            .into_iter()
            .map(|row| (row.row.height(), row.value))
            .collect();
        pairs.sort();
        pairs
    }

    // PRJ-06, PRJ-07
    #[test]
    fn segment_reads_match_bulk_build() -> Result<(), TestError> {
        let blocks = facts_chain(BLOCKS);
        let caps = IndexCapabilities::HISTORICAL.with_compact_filters(true);
        let live_store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&live_store), 1)?;
        for block in &blocks {
            let prepared = writer.prepare_block_from_facts(caps, block.clone())?;
            let mut batch = PreparedBatch::new(PreparedBatchLimits {
                max_rows: usize::MAX,
                max_bytes: usize::MAX,
            });
            assert!(
                batch.try_push(prepared).is_ok(),
                "one block per batch is admitted"
            );
            writer.commit_forward(batch)?;
        }
        let live_indexer = Indexer::new(Arc::clone(&live_store));
        let live = live_indexer.snapshot()?;

        let bulk_dir = tempfile::tempdir()?;
        let scratch = tempfile::tempdir()?;
        let bulk_store = Arc::new(RocksDbStore::open(bulk_dir.path())?);
        let coverage = BulkSegmentBuilder::new(
            Arc::new(UnboundedBudget),
            None,
            scratch.path().to_path_buf(),
        )
        .build_and_ingest(bulk_store.as_ref(), 1, &blocks)
        .map_err(|e| e.to_string())?;
        let tx_count: usize = blocks.iter().map(|block| block.txs.len()).sum();
        publish_sealed(
            bulk_store.as_ref(),
            1,
            coverage,
            u32::try_from(tx_count)?,
            caps,
        )?;
        let bulk_indexer = Indexer::new(Arc::clone(&bulk_store));
        let bulk = bulk_indexer.snapshot()?;

        let mut funding_seen = 0_usize;
        let mut tx_seen = 0_usize;
        let mut spend_seen = 0_usize;
        for seed in 0..BLOCKS {
            let scripthash = ScriptHash::from_script_bytes(&script_for(seed));
            let expected = segment_rows(bulk.funding_rows(scripthash, SCAN_ALL)?.rows);
            let actual = segment_rows(live.funding_rows(scripthash, SCAN_ALL)?.rows);
            funding_seen += actual.len();
            assert_eq!(actual, expected, "funding rows for script seed {seed}");
        }
        assert!(funding_seen > 0, "the fixture produces funding rows");

        for height in 0..BLOCKS {
            let txid = Txid(Hash256::from_le_bytes(&coinbase_txid(height)));
            let expected = segment_rows(bulk.transaction_rows(&txid, SCAN_ALL)?.rows);
            let actual = segment_rows(live.transaction_rows(&txid, SCAN_ALL)?.rows);
            tx_seen += actual.len();
            assert_eq!(actual, expected, "transaction rows at height {height}");

            let outpoint = OutPoint::new(txid, 0);
            let expected = segment_rows(bulk.spending_rows(&outpoint, SCAN_ALL)?.rows);
            let actual = segment_rows(live.spending_rows(&outpoint, SCAN_ALL)?.rows);
            spend_seen += actual.len();
            assert_eq!(actual, expected, "spending rows at height {height}");

            let hash = block_hash(height);
            let live_filter = live.compact_filter(height, &hash)?;
            assert!(
                live_filter.is_some(),
                "live serves the compact filter at height {height}"
            );
            assert_eq!(
                live_filter,
                bulk.compact_filter(height, &hash)?,
                "compact filter at height {height}"
            );
        }
        assert!(tx_seen > 0, "the fixture produces transaction rows");
        assert!(spend_seen > 0, "the fixture produces spending rows");
        Ok(())
    }
}
mod script_live {
    use crate::support::{TestError, common};

    use bitcoin_rs_projection::IndexReader;
    use common::MemoryStore;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use bitcoin::absolute::LockTime;
    use bitcoin::block::{self, Header};
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Txid, Witness,
    };
    use bitcoin_rs_consensus::primitives::{
        Hash256, OutPoint as NativeOutPoint, Txid as NativeTxid,
    };
    use bitcoin_rs_projection::{
        ConsumerCursorUpdate, IndexCapabilities, IndexCapability, IndexError, IndexWatermark,
        IndexWatermarks, IndexWriter, MAX_LIVE_SCRIPT_SIZE, PreparedBatch, PreparedBatchLimits,
        ScriptHash, ScriptLiveCoin, ScriptLiveRow, ScriptLiveValueError, SpentCoin, SpentCoins,
    };
    use bitcoin_rs_storage::{ColumnFamily, KvStore};
    use proptest::prelude::*;

    fn commit_rollback_one_with_spent_scripts<S: KvStore>(
        writer: &mut IndexWriter<S>,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
        spent_scripts: &dyn SpentCoins,
    ) -> Result<(), IndexError> {
        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            capabilities,
            prev,
            body,
            ConsumerCursorUpdate::Clear,
            spent_scripts,
        )
    }

    #[derive(Default)]
    struct MapScripts(hashbrown::HashMap<(Txid, u32), FixtureCoin>);

    struct FixtureCoin {
        script: Vec<u8>,
        value: u64,
        height: u32,
        coinbase: bool,
    }

    impl MapScripts {
        fn insert(&mut self, outpoint: OutPoint, coin: FixtureCoin) {
            self.0.insert((outpoint.txid, outpoint.vout), coin);
        }
    }

    impl FixtureCoin {
        /// A coin the fixture chain paid to `script` at `height`; the canonical
        /// value of fixture coinbase outputs is 50 sat.
        fn paying(script: &ScriptBuf, height: u32) -> Self {
            Self {
                script: script.to_bytes(),
                value: 50,
                height,
                coinbase: true,
            }
        }

        /// A coin that predates the fixture chain; only its script identity is
        /// observable through the index.
        fn external(script: &ScriptBuf) -> Self {
            Self {
                script: script.to_bytes(),
                value: 0,
                height: 0,
                coinbase: false,
            }
        }
    }

    impl SpentCoins for MapScripts {
        fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<SpentCoin<'_>> {
            self.0
                .get(&(Txid::from_byte_array(*txid), vout))
                .map(|coin| SpentCoin {
                    script: &coin.script,
                    value: coin.value,
                    height: coin.height,
                    coinbase: coin.coinbase,
                })
        }
    }

    fn coinbase(tag: u8) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![tag]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: script(0xc0 ^ tag),
            }],
        }
    }

    fn script(tag: u8) -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x51, tag])
    }

    fn spend(inputs: &[OutPoint], outputs: &[ScriptBuf]) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .map(|previous_output| TxIn {
                    previous_output: *previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs
                .iter()
                .map(|script_pubkey| TxOut {
                    value: Amount::from_sat(10),
                    script_pubkey: script_pubkey.clone(),
                })
                .collect(),
        }
    }

    fn block_bytes(prev: [u8; 32], txdata: Vec<Transaction>) -> (Vec<u8>, [u8; 32]) {
        let block = Block {
            header: Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::from_byte_array(prev),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata,
        };
        let hash = block.block_hash().to_byte_array();
        (serialize(&block), hash)
    }

    struct Chain {
        writer: IndexWriter<MemoryStore>,
        tip: [u8; 32],
        height: u32,
    }

    impl Chain {
        fn new() -> Result<Self, TestError> {
            let store = Arc::new(MemoryStore::default());
            let writer = IndexWriter::open(store, 0)?;
            Ok(Self {
                writer,
                tip: [0_u8; 32],
                height: 0,
            })
        }

        fn connect(
            &mut self,
            txdata: Vec<Transaction>,
            anchor: &MapScripts,
        ) -> Result<[u8; 32], IndexError> {
            let (body, hash) = block_bytes(self.tip, txdata);
            let prepared = self.writer.prepare_block_with_spent_scripts(
                IndexCapabilities::TX_AND_SCRIPTS,
                self.height,
                hash,
                &body,
                anchor,
            )?;
            let mut batch = PreparedBatch::new(PreparedBatchLimits {
                max_rows: 10_000,
                max_bytes: 10_000_000,
            });
            assert!(batch.try_push(prepared).is_ok(), "batch must admit block");
            self.writer.commit_forward(batch)?;
            self.tip = hash;
            self.height += 1;
            Ok(hash)
        }

        fn live(&self, script: &ScriptBuf) -> Vec<OutPoint> {
            let mut outpoints = self
                .writer
                .indexer()
                .iter_live_outpoints(ScriptHash::from_script_bytes(script.as_bytes()))
                .unwrap_or_else(|error| panic!("live scan failed: {error}"))
                .into_iter()
                .map(|outpoint| {
                    let txid = outpoint.txid;
                    let vout = outpoint.vout;
                    bitcoin::OutPoint {
                        txid: bitcoin::Txid::from_byte_array(*txid.as_bytes()),
                        vout,
                    }
                })
                .collect::<Vec<_>>();
            outpoints.sort_by_key(|outpoint| (*outpoint.txid.as_byte_array(), outpoint.vout));
            outpoints
        }
    }

    fn persistent_writer_live_roundtrip<S: KvStore>(
        open: impl Fn() -> Result<S, bitcoin_rs_storage::StorageError>,
        capabilities: IndexCapabilities,
    ) -> Result<(), TestError> {
        let store = Arc::new(open()?);
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        let empty = MapScripts::default();
        let (genesis, genesis_hash) = block_bytes([0; 32], vec![coinbase(0)]);
        let mut funding_tx = coinbase(1);
        funding_tx.output.push(funding_tx.output[0].clone());
        funding_tx.output[0].script_pubkey = script(0xab);
        let (funding, funding_hash) = block_bytes(genesis_hash, vec![funding_tx.clone()]);
        for (height, body, hash) in [(0, &genesis, genesis_hash), (1, &funding, funding_hash)] {
            let prepared = writer.prepare_block_with_spent_scripts(
                capabilities,
                height,
                hash,
                body,
                &empty,
            )?;
            writer.commit_forward(common::single_block_batch(prepared))?;
        }
        let funding_tip = IndexWatermark {
            height: 1,
            hash: funding_hash,
        };
        assert_eq!(
            writer.watermarks()?,
            IndexWatermarks {
                compact_filters: None,
                tx_lookup: (capabilities != IndexCapabilities::SCRIPT_LIVE).then_some(funding_tip),
                script_history: (capabilities == IndexCapabilities::TX_AND_SCRIPTS)
                    .then_some(funding_tip),
                script_live: (capabilities != IndexCapabilities::TX_LOOKUP).then_some(funding_tip),
            }
        );
        if capabilities == IndexCapabilities::TX_LOOKUP {
            return tx_lookup_only_reopen(open, store, writer, funding_tip);
        }
        let wallet = funding_tx.output[1].script_pubkey.clone();
        let scripthash = ScriptHash::from_script_bytes(wallet.as_bytes());
        let outpoint = OutPoint::new(funding_tx.compute_txid(), 1);
        let native = NativeOutPoint::new(
            NativeTxid(Hash256::from_le_bytes(outpoint.txid.as_byte_array())),
            1,
        );
        let row = ScriptLiveRow::new(scripthash, &native);
        assert_eq!(row.as_bytes().len(), 43);
        let Some(stored) = store.get(ColumnFamily::ScriptLive, row.as_bytes())? else {
            return Err(TestError::from("the funding output row is stored"));
        };
        let stored_coin = bitcoin_rs_projection::ScriptLiveCoin::decode_value(&stored)
            .map_err(|_| TestError::from("format 8 rows carry a coin payload"))?;
        assert_eq!(stored_coin.scripthash, scripthash);
        assert_eq!(stored_coin.value, funding_tx.output[1].value.to_sat());
        assert_eq!(stored_coin.height, 1);
        assert!(stored_coin.coinbase);
        let scan = writer.snapshot()?.live_rows(
            scripthash,
            bitcoin_rs_storage::PrefixScanLimit {
                max_rows: 10,
                max_bytes: 1_024,
            },
        )?;
        assert!(scan.complete);
        assert_eq!(scan.rows.len(), 1);
        assert_eq!(scan.rows[0].as_bytes(), row.as_bytes());

        let mut anchor = MapScripts::default();
        anchor.insert(outpoint, FixtureCoin::paying(&wallet, 1));
        let (spending, spending_hash) = block_bytes(
            funding_hash,
            vec![coinbase(2), spend(&[outpoint], &[script(0xdd)])],
        );
        let prepared = writer.prepare_block_with_spent_scripts(
            capabilities,
            2,
            spending_hash,
            &spending,
            &anchor,
        )?;
        writer.commit_forward(common::single_block_batch(prepared))?;
        assert_eq!(store.get(ColumnFamily::ScriptLive, row.as_bytes())?, None);
        commit_rollback_one_with_spent_scripts(
            &mut writer,
            capabilities,
            Some(IndexWatermark {
                height: 1,
                hash: funding_hash,
            }),
            &spending,
            &anchor,
        )?;
        store.flush()?;
        drop(writer);
        drop(store);

        let store = Arc::new(open()?);
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        assert_eq!(
            writer.indexer().iter_live_outpoints(scripthash)?,
            vec![native]
        );
        commit_rollback_one_with_spent_scripts(
            &mut writer,
            capabilities,
            Some(IndexWatermark {
                height: 0,
                hash: genesis_hash,
            }),
            &funding,
            &empty,
        )?;
        assert_eq!(store.get(ColumnFamily::ScriptLive, row.as_bytes())?, None);
        seed_live_and_reopen(open, store, writer, native, scripthash)
    }

    fn tx_lookup_only_reopen<S: KvStore>(
        open: impl Fn() -> Result<S, bitcoin_rs_storage::StorageError>,
        store: Arc<S>,
        writer: IndexWriter<S>,
        funding_tip: IndexWatermark,
    ) -> Result<(), TestError> {
        assert_eq!(
            writer
                .indexer()
                .capability_watermark(IndexCapability::ScriptLive)?,
            None
        );
        assert!(
            store
                .iter_prefix(ColumnFamily::ScriptLive, &[])?
                .next()
                .is_none()
        );
        store.flush()?;
        drop(writer);
        drop(store);
        let writer = IndexWriter::open(Arc::new(open()?), 1)?;
        assert_eq!(
            writer
                .indexer()
                .capability_watermark(IndexCapability::TxLookup)?,
            Some(funding_tip)
        );
        assert_eq!(
            writer
                .indexer()
                .capability_watermark(IndexCapability::ScriptLive)?,
            None
        );
        Ok(())
    }

    fn seed_row(outpoint: &NativeOutPoint, coin: &ScriptLiveCoin) -> Result<Vec<u8>, TestError> {
        let row = ScriptLiveRow::new(coin.scripthash, outpoint);
        let mut bytes = row.as_bytes().to_vec();
        bytes.extend_from_slice(&coin.encode_value()?);
        Ok(bytes)
    }

    fn seed_live_and_reopen<S: KvStore>(
        open: impl Fn() -> Result<S, bitcoin_rs_storage::StorageError>,
        store: Arc<S>,
        mut writer: IndexWriter<S>,
        native: NativeOutPoint,
        scripthash: ScriptHash,
    ) -> Result<(), TestError> {
        writer.reset_capabilities(IndexCapabilities::SCRIPT_LIVE)?;
        let (_, before_seed) = writer.fenced_watermarks()?;
        let seed_tip = IndexWatermark {
            height: 42,
            hash: [0x42; 32],
        };
        let high_vout = NativeOutPoint::new(native.txid, 256);
        let coins = [
            (
                native,
                bitcoin_rs_projection::ScriptLiveCoin::new(scripthash, 1, 7, false),
            ),
            (
                high_vout,
                bitcoin_rs_projection::ScriptLiveCoin::new(scripthash, 2, 7, false),
            ),
        ];
        let rows = coins
            .into_iter()
            .map(|(outpoint, coin)| seed_row(&outpoint, &coin))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(writer.stage_script_live_rows(&mut rows.into_iter())?, 2);
        writer.publish_script_live_seed(seed_tip)?;
        let (_, after_seed) = writer.fenced_watermarks()?;
        assert_eq!(after_seed.script_live, Some(seed_tip));
        assert_eq!(after_seed.tx_lookup, before_seed.tx_lookup);
        assert_eq!(after_seed.script_history, before_seed.script_history);
        assert!(matches!(
            writer.publish_script_live_seed(seed_tip),
            Err(IndexError::LiveAlreadySeeded)
        ));
        store.flush()?;
        drop(writer);
        drop(store);
        let writer = IndexWriter::open(Arc::new(open()?), 1)?;
        let live = writer.indexer().iter_live_outpoints(scripthash)?;
        assert_eq!(live.len(), 2);
        assert!(live.contains(&native) && live.contains(&high_vout));
        assert_eq!(
            writer
                .indexer()
                .capability_watermark(IndexCapability::ScriptLive)?,
            Some(seed_tip)
        );
        Ok(())
    }

    #[test]
    fn rocksdb_writer_live_roundtrip() -> Result<(), TestError> {
        for capabilities in [
            IndexCapabilities::SCRIPT_LIVE,
            IndexCapabilities::TX_AND_SCRIPTS,
            IndexCapabilities::TX_LOOKUP,
        ] {
            let temp = tempfile::TempDir::new()?;
            persistent_writer_live_roundtrip(
                || bitcoin_rs_storage::RocksDbStore::open(temp.path()),
                capabilities,
            )?;
        }
        Ok(())
    }

    #[test]
    fn live_rows_follow_connect_spend_and_disconnect() -> Result<(), TestError> {
        let mut chain = Chain::new()?;
        let empty = MapScripts::default();

        chain.connect(vec![coinbase(0)], &empty)?;

        let wallet = script(0xaa);
        let pay = spend(&[OutPoint::null()], &[wallet.clone(), wallet.clone()]);
        let external = OutPoint {
            txid: Txid::from_byte_array([7_u8; 32]),
            vout: 0,
        };
        let funding_script = script(0xbb);
        let pay = {
            let mut pay = pay;
            pay.input[0].previous_output = external;
            pay
        };
        let pay_txid = pay.compute_txid();
        let mut anchor = MapScripts::default();
        anchor.insert(external, FixtureCoin::external(&funding_script));
        chain.connect(vec![coinbase(1), pay], &anchor)?;

        let o0 = OutPoint {
            txid: pay_txid,
            vout: 0,
        };
        let o1 = OutPoint {
            txid: pay_txid,
            vout: 1,
        };
        assert_eq!(chain.live(&wallet), sorted(vec![o0, o1]));

        let sweep = spend(&[o0], &[script(0xcc)]);
        let mut anchor2 = MapScripts::default();
        anchor2.insert(o0, FixtureCoin::paying(&wallet, chain.height));
        let (body2, hash2) = block_bytes(chain.tip, vec![coinbase(2), sweep]);
        let prepared = chain.writer.prepare_block_with_spent_scripts(
            IndexCapabilities::TX_AND_SCRIPTS,
            chain.height,
            hash2,
            &body2,
            &anchor2,
        )?;
        let batch = common::batch_with_limits(
            prepared,
            PreparedBatchLimits {
                max_rows: 10_000,
                max_bytes: 10_000_000,
            },
        );
        chain.writer.commit_forward(batch)?;
        assert_eq!(chain.live(&wallet), vec![o1]);

        let prev = IndexWatermark {
            height: 1,
            hash: chain.tip,
        };
        commit_rollback_one_with_spent_scripts(
            &mut chain.writer,
            IndexCapabilities::TX_AND_SCRIPTS,
            Some(prev),
            &body2,
            &anchor2,
        )?;
        assert_eq!(chain.live(&wallet), sorted(vec![o0, o1]));
        assert_eq!(chain.live(&script(0xcc)), Vec::<OutPoint>::new());
        Ok(())
    }

    #[test]
    fn disconnect_restores_the_full_coin_payload() -> Result<(), TestError> {
        let mut chain = Chain::new()?;
        let empty = MapScripts::default();
        chain.connect(vec![coinbase(0)], &empty)?;

        let wallet = script(0xaa);
        let funding = spend(&[OutPoint::null()], std::slice::from_ref(&wallet));
        let funding_txid = funding.compute_txid();
        let funding_outpoint = OutPoint {
            txid: funding_txid,
            vout: 0,
        };
        chain.connect(vec![funding], &MapScripts::default())?;

        let sweep = spend(&[funding_outpoint], &[script(0xdd)]);
        let mut anchor = MapScripts::default();
        anchor.insert(funding_outpoint, FixtureCoin::paying(&wallet, 1));
        let (body, hash) = block_bytes(chain.tip, vec![coinbase(1), sweep]);
        let prepared = chain.writer.prepare_block_with_spent_scripts(
            IndexCapabilities::TX_AND_SCRIPTS,
            chain.height,
            hash,
            &body,
            &anchor,
        )?;
        let batch = common::batch_with_limits(
            prepared,
            PreparedBatchLimits {
                max_rows: 10_000,
                max_bytes: 10_000_000,
            },
        );
        chain.writer.commit_forward(batch)?;
        assert_eq!(chain.live(&wallet), Vec::<OutPoint>::new());

        let prev = IndexWatermark {
            height: 1,
            hash: chain.tip,
        };
        commit_rollback_one_with_spent_scripts(
            &mut chain.writer,
            IndexCapabilities::TX_AND_SCRIPTS,
            Some(prev),
            &body,
            &anchor,
        )?;

        let scripthash = bitcoin_rs_projection::ScriptHash::from_script_bytes(wallet.as_bytes());
        let scan = chain
            .writer
            .snapshot()?
            .live_rows(
                scripthash,
                bitcoin_rs_storage::PrefixScanLimit {
                    max_rows: 10,
                    max_bytes: 10_000,
                },
            )
            .map_err(TestError::from)?;
        assert_eq!(scan.rows.len(), 1);
        let coin = scan.coins[0];
        assert_eq!(coin.scripthash, scripthash);
        assert_eq!(coin.value, 50);
        assert_eq!(coin.height, 1);
        assert!(coin.coinbase);
        Ok(())
    }

    #[test]
    fn live_rows_restore_a_replaced_outpoint() -> Result<(), TestError> {
        let mut chain = Chain::new()?;
        chain.connect(vec![coinbase(0)], &MapScripts::default())?;

        let external = OutPoint {
            txid: Txid::from_byte_array([0x71_u8; 32]),
            vout: 0,
        };
        let old_script = script(0x72);
        let new_script = script(0x73);
        let mut creator = spend(&[external], std::slice::from_ref(&new_script));
        creator.input[0].previous_output = external;
        let creator_txid = creator.compute_txid();
        let replaced = OutPoint {
            txid: creator_txid,
            vout: 0,
        };
        let mut anchor = MapScripts::default();
        anchor.insert(external, FixtureCoin::external(&script(0x74)));
        anchor.insert(replaced, FixtureCoin::external(&old_script));

        let (body, hash) = block_bytes(chain.tip, vec![coinbase(1), creator]);
        let prepared = chain.writer.prepare_block_with_spent_scripts(
            IndexCapabilities::TX_AND_SCRIPTS,
            chain.height,
            hash,
            &body,
            &anchor,
        )?;
        let batch = common::batch_with_limits(
            prepared,
            PreparedBatchLimits {
                max_rows: 10_000,
                max_bytes: 10_000_000,
            },
        );
        chain.writer.commit_forward(batch)?;

        assert_eq!(chain.live(&old_script), Vec::<OutPoint>::new());
        assert_eq!(chain.live(&new_script), vec![replaced]);

        let prev = IndexWatermark {
            height: 0,
            hash: chain.tip,
        };
        commit_rollback_one_with_spent_scripts(
            &mut chain.writer,
            IndexCapabilities::TX_AND_SCRIPTS,
            Some(prev),
            &body,
            &anchor,
        )?;
        assert_eq!(chain.live(&new_script), Vec::<OutPoint>::new());
        assert_eq!(chain.live(&old_script), vec![replaced]);
        Ok(())
    }

    #[test]
    fn same_block_create_and_spend_cancels_without_an_anchor() -> Result<(), TestError> {
        let mut chain = Chain::new()?;
        let empty = MapScripts::default();
        chain.connect(vec![coinbase(0)], &empty)?;

        let transient = script(0xdd);
        let transient_op_return = ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x01]);
        let transient_oversized = ScriptBuf::from_bytes(vec![0x51; MAX_LIVE_SCRIPT_SIZE + 1]);
        let survivor = script(0xee);
        let external = OutPoint {
            txid: Txid::from_byte_array([9_u8; 32]),
            vout: 3,
        };
        let creator = {
            let mut tx = spend(
                &[external],
                &[
                    transient.clone(),
                    transient_op_return.clone(),
                    transient_oversized.clone(),
                ],
            );
            tx.input[0].previous_output = external;
            tx
        };
        let creator_txid = creator.compute_txid();
        let spender = spend(
            &[
                OutPoint {
                    txid: creator_txid,
                    vout: 0,
                },
                OutPoint {
                    txid: creator_txid,
                    vout: 1,
                },
                OutPoint {
                    txid: creator_txid,
                    vout: 2,
                },
            ],
            std::slice::from_ref(&survivor),
        );
        let spender_txid = spender.compute_txid();

        let mut anchor = MapScripts::default();
        anchor.insert(external, FixtureCoin::external(&script(0xef)));
        chain.connect(vec![coinbase(1), creator, spender], &anchor)?;

        assert_eq!(chain.live(&transient), Vec::<OutPoint>::new());
        assert_eq!(chain.live(&transient_op_return), Vec::<OutPoint>::new());
        assert_eq!(chain.live(&transient_oversized), Vec::<OutPoint>::new());
        assert_eq!(
            chain.live(&survivor),
            vec![OutPoint {
                txid: spender_txid,
                vout: 0,
            }]
        );
        Ok(())
    }

    #[test]
    fn unresolvable_spends_fail_closed() -> Result<(), TestError> {
        let mut chain = Chain::new()?;
        let empty = MapScripts::default();
        chain.connect(vec![coinbase(0)], &empty)?;

        let external = OutPoint {
            txid: Txid::from_byte_array([5_u8; 32]),
            vout: 1,
        };
        let tx = {
            let mut tx = spend(&[external], &[script(0x11)]);
            tx.input[0].previous_output = external;
            tx
        };
        let (body, hash) = block_bytes(chain.tip, vec![coinbase(1), tx]);

        let unresolved = chain.writer.prepare_block_with_spent_scripts(
            IndexCapabilities::TX_AND_SCRIPTS,
            chain.height,
            hash,
            &body,
            &empty,
        );
        let unresolved_err = unresolved.err();
        assert!(
            matches!(
                unresolved_err,
                Some(IndexError::MissingSpentCoin { vout: 1, .. })
            ),
            "a spend the anchor cannot resolve must refuse the block: {unresolved_err:?}"
        );

        let anchorless = chain.writer.prepare_block_for(
            IndexCapabilities::TX_AND_SCRIPTS,
            chain.height,
            hash,
            &body,
        );
        let anchorless_err = anchorless.err();
        assert!(
            matches!(anchorless_err, Some(IndexError::MissingSpentScripts)),
            "the anchorless path must refuse ScriptLive: {anchorless_err:?}"
        );
        Ok(())
    }

    #[test]
    fn live_predicate_matches_utxo_admission_not_history() -> Result<(), TestError> {
        let mut chain = Chain::new()?;
        let empty = MapScripts::default();
        chain.connect(vec![coinbase(0)], &empty)?;

        let op_return = ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x02]);
        let oversized = ScriptBuf::from_bytes(vec![0x51; MAX_LIVE_SCRIPT_SIZE + 1]);
        let normal = script(0x22);
        let external = OutPoint {
            txid: Txid::from_byte_array([6_u8; 32]),
            vout: 0,
        };
        let tx = {
            let mut tx = spend(
                &[external],
                &[op_return.clone(), oversized.clone(), normal.clone()],
            );
            tx.input[0].previous_output = external;
            tx
        };
        let txid = tx.compute_txid();
        let mut anchor = MapScripts::default();
        anchor.insert(external, FixtureCoin::external(&script(0x23)));
        chain.connect(vec![coinbase(1), tx], &anchor)?;

        assert_eq!(chain.live(&op_return), Vec::<OutPoint>::new());
        assert_eq!(chain.live(&oversized), Vec::<OutPoint>::new());
        assert_eq!(chain.live(&normal), vec![OutPoint { txid, vout: 2 }]);

        let funding = {
            use bitcoin_rs_projection::IndexReader;
            chain
                .writer
                .indexer()
                .snapshot()?
                .funding_rows(
                    ScriptHash::from_script_bytes(oversized.as_bytes()),
                    bitcoin_rs_storage::PrefixScanLimit {
                        max_rows: 100_000,
                        max_bytes: 64 << 20,
                    },
                )?
                .rows
        };
        assert_eq!(
            funding.len(),
            1,
            "history must keep the oversized-script funding row"
        );
        Ok(())
    }

    struct NoSpend;

    static NO_SPEND_SCRIPT: [u8; 2] = [0x51, 0x01];

    impl bitcoin_rs_projection::SpentCoins for NoSpend {
        fn spent_coin(
            &self,
            _txid: &[u8; 32],
            _vout: u32,
        ) -> Option<bitcoin_rs_projection::SpentCoin<'_>> {
            Some(bitcoin_rs_projection::SpentCoin {
                script: NO_SPEND_SCRIPT.as_slice(),
                value: 0,
                height: 0,
                coinbase: false,
            })
        }
    }

    #[test]
    fn live_and_history_watermarks_advance_independently() -> Result<(), TestError> {
        let mut chain = Chain::new()?;
        let (body, hash) = block_bytes(chain.tip, vec![coinbase(0)]);
        let prepared = chain.writer.prepare_block_with_spent_scripts(
            IndexCapabilities::HISTORICAL,
            0,
            hash,
            &body,
            &NoSpend,
        )?;
        let batch = common::batch_with_limits(
            prepared,
            PreparedBatchLimits {
                max_rows: 10_000,
                max_bytes: 10_000_000,
            },
        );
        chain.writer.commit_forward(batch)?;

        let watermarks = chain.writer.watermarks()?;
        assert!(watermarks.script_history.is_some());
        assert!(
            watermarks.script_live.is_none(),
            "a historical commit must not stamp the live cursor"
        );
        Ok(())
    }

    #[test]
    fn seeding_resets_partial_rows_and_stamps_once() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        let writer = IndexWriter::open(Arc::clone(&store), 0)?;

        let wallet = script(0x44);
        let scripthash = ScriptHash::from_script_bytes(wallet.as_bytes());
        let stale_script = script(0x45);
        let stale_scripthash = ScriptHash::from_script_bytes(stale_script.as_bytes());
        let stale_outpoint =
            NativeOutPoint::new(NativeTxid(Hash256::from_le_bytes(&[0x32_u8; 32])), 0);
        let stale_row = ScriptLiveRow::new(stale_scripthash, &stale_outpoint);
        let stale_coin =
            bitcoin_rs_projection::ScriptLiveCoin::new(stale_scripthash, 500, 1, false);
        let mut partial = store.new_batch();
        partial.put(
            ColumnFamily::ScriptLive,
            stale_row.as_bytes(),
            &stale_coin.encode_value()?,
        );
        store.write(partial)?;
        let bare_row = stale_row.as_bytes().to_vec();
        assert!(matches!(
            writer.stage_script_live_rows(&mut [bare_row].into_iter()),
            Err(IndexError::InvalidLiveRowValue { len: 43 })
        ));
        assert!(
            writer
                .indexer()
                .capability_watermark(IndexCapability::ScriptLive)?
                .is_none()
        );
        assert!(
            writer
                .indexer()
                .iter_live_outpoints(stale_scripthash)?
                .is_empty(),
            "partial rows must remain unavailable until the live watermark is stamped"
        );

        writer.reset_capabilities(IndexCapabilities::SCRIPT_LIVE)?;
        assert!(
            writer
                .indexer()
                .capability_watermark(IndexCapability::ScriptLive)?
                .is_none()
        );
        assert!(
            writer
                .indexer()
                .iter_live_outpoints(stale_scripthash)?
                .is_empty(),
            "reset must remove rows left while the live watermark was absent"
        );

        let coins = (0_u32..3)
            .map(|vout| {
                (
                    NativeOutPoint::new(NativeTxid(Hash256::from_le_bytes(&[0x33_u8; 32])), vout),
                    bitcoin_rs_projection::ScriptLiveCoin::new(scripthash, 3, 8, false),
                )
            })
            .collect::<Vec<_>>();
        let seed_tip = IndexWatermark {
            height: 42,
            hash: [0x42_u8; 32],
        };

        let rows = coins
            .iter()
            .map(|(outpoint, coin)| seed_row(outpoint, coin))
            .collect::<Result<Vec<_>, _>>()?;
        let written = writer.stage_script_live_rows(&mut rows.into_iter())?;
        assert_eq!(written, 3);
        assert_eq!(
            writer
                .indexer()
                .capability_watermark(IndexCapability::ScriptLive)?,
            None,
            "SNP-07: staged rows stay unpublished until the seed tip commits"
        );
        writer.publish_script_live_seed(seed_tip)?;
        assert_eq!(
            writer
                .indexer()
                .capability_watermark(IndexCapability::ScriptLive)?,
            Some(seed_tip)
        );
        assert_eq!(writer.indexer().iter_live_outpoints(scripthash)?.len(), 3);

        let again = writer.publish_script_live_seed(seed_tip);
        assert!(
            matches!(again, Err(IndexError::LiveAlreadySeeded)),
            "re-seeding over a stamped watermark must be refused: {again:?}"
        );
        Ok(())
    }

    #[test]
    fn seed_stream_fenced_write_failure_does_not_publish_watermark() -> Result<(), TestError> {
        let store = Arc::new(MemoryStore::default());
        let writer = IndexWriter::open(Arc::clone(&store), 0)?;
        store.fail_next_fenced_write.store(true, Ordering::SeqCst);
        let scripthash = ScriptHash::from_script_bytes(script(0x46).as_bytes());
        let coins = (0_u32..4_096)
            .map(|vout| {
                (
                    NativeOutPoint::new(NativeTxid(Hash256::from_le_bytes(&[0x34_u8; 32])), vout),
                    bitcoin_rs_projection::ScriptLiveCoin::new(scripthash, 1, 0, false),
                )
            })
            .collect::<Vec<_>>();
        let rows = coins
            .iter()
            .map(|(outpoint, coin)| seed_row(outpoint, coin))
            .collect::<Result<Vec<_>, _>>()?;
        let result = writer.stage_script_live_rows(&mut rows.into_iter());
        assert!(
            matches!(result, Err(IndexError::Storage(_))),
            "a fenced batch failure must surface: {result:?}"
        );
        assert!(
            writer
                .indexer()
                .capability_watermark(IndexCapability::ScriptLive)?
                .is_none(),
            "the live watermark must stay unpublished after a seed write failure"
        );
        assert!(
            writer.indexer().iter_live_outpoints(scripthash)?.is_empty(),
            "partial seed rows must remain unavailable without a live watermark"
        );
        Ok(())
    }

    fn sorted(mut outpoints: Vec<OutPoint>) -> Vec<OutPoint> {
        outpoints.sort_unstable();
        outpoints
    }

    // IDX-04
    #[test]
    fn leftover_capabilities_are_persisted_families_outside_the_selection() {
        let cursor = IndexWatermark {
            height: 1,
            hash: [1_u8; 32],
        };
        let watermarks = IndexWatermarks {
            compact_filters: None,
            tx_lookup: Some(cursor),
            script_history: Some(cursor),
            script_live: Some(cursor),
        };
        assert_eq!(
            IndexCapabilities::SCRIPT_LIVE.leftover(watermarks),
            IndexCapabilities::HISTORICAL
        );
        assert!(
            IndexCapabilities::TX_AND_SCRIPTS
                .leftover(watermarks)
                .is_empty()
        );
    }

    const COIN: u64 = 100_000_000;
    const MAX_MONEY: u64 = 21_000_000 * COIN;

    fn row_codec() -> impl proptest::strategy::Strategy<Value = ScriptLiveCoin> {
        (
            proptest::array::uniform32(proptest::arbitrary::any::<u8>()),
            0..=MAX_MONEY,
            proptest::arbitrary::any::<u32>(),
            proptest::arbitrary::any::<bool>(),
        )
            .prop_map(|(scripthash, value, height, coinbase)| {
                ScriptLiveCoin::new(
                    ScriptHash::from_byte_array(scripthash),
                    value,
                    height,
                    coinbase,
                )
            })
    }

    // PRJ-11
    #[test]
    fn script_live_value_matches_compress_amount_vectors() -> Result<(), TestError> {
        let vectors: [(u64, &[u8]); 6] = [
            (0, &[0x00]),
            (1, &[0x01]),
            (1_000_000, &[0x07]),
            (COIN, &[0x09]),
            (50 * COIN, &[0x32]),
            (21_000_000 * COIN, &[0xC0, 0xDE, 0x81, 0x0A]),
        ];
        for (amount, compressed) in vectors {
            let coin = ScriptLiveCoin::new(ScriptHash::from_byte_array([7; 32]), amount, 0, false);
            let encoded = coin.encode_value()?;
            let mut expected = vec![7_u8; 32];
            expected.extend_from_slice(compressed);
            expected.push(0x00);
            assert_eq!(encoded, expected, "compress_amount({amount}) vector");
            assert_eq!(ScriptLiveCoin::decode_value(&encoded)?, coin);
        }
        Ok(())
    }

    // PRJ-11
    #[test]
    fn script_live_value_round_trips_core_test_encode_sweeps() -> Result<(), TestError> {
        fn assert_round_trip(amount: u64) -> Result<(), TestError> {
            let coin =
                ScriptLiveCoin::new(ScriptHash::from_byte_array([9; 32]), amount, 842_113, true);
            let encoded = coin.encode_value()?;
            assert_eq!(ScriptLiveCoin::decode_value(&encoded)?, coin);
            Ok(())
        }
        for amount in 1..=100_000 {
            assert_round_trip(amount)?;
        }
        for amount in 1..=10_000 {
            assert_round_trip(amount * 1_000_000)?;
        }
        for amount in 1..=10_000 {
            assert_round_trip(amount * COIN)?;
        }
        for amount in 1..=420_000 {
            assert_round_trip(amount * 50 * COIN)?;
        }
        let vectors: [(u64, &[u8], Option<u64>); 11] = [
            (0, &[0x00], Some(0)),
            (1, &[0x01], Some(1)),
            (7, &[0x07], Some(1_000_000)),
            (9, &[0x09], Some(COIN)),
            (50, &[0x32], Some(50 * COIN)),
            (127, &[0x7F], Some(14_000_000)),
            (128, &[0x80, 0x01], Some(140_000_000)),
            (300, &[0xAC, 0x02], Some(30_000_000_000)),
            (16_384, &[0x80, 0x80, 0x01], Some(1_821_000)),
            (21_000_000, &[0xC0, 0xDE, 0x81, 0x0A], Some(MAX_MONEY)),
            (100_000_000, &[0x80, 0xC2, 0xD7, 0x2F], None),
        ];
        for (compressed, varint, expected) in vectors {
            let mut bytes = vec![0_u8; 32];
            bytes.extend_from_slice(varint);
            bytes.push(0x00);
            match expected {
                Some(value) => {
                    let coin = ScriptLiveCoin::decode_value(&bytes).map_err(|e| e.to_string())?;
                    assert_eq!(coin.value, value, "decompressed value of {compressed}");
                    assert_eq!(coin.height, 0, "decode vector carries height zero");
                    assert!(!coin.coinbase, "decode vector is not a coinbase");
                    assert_eq!(coin.scripthash, ScriptHash::from_byte_array([0; 32]));
                }
                None => assert_eq!(
                    ScriptLiveCoin::decode_value(&bytes),
                    Err(ScriptLiveValueError::AmountOverflow),
                    "compressed {compressed} exceeds the money range"
                ),
            }
        }
        Ok(())
    }

    // PRJ-11
    #[test]
    fn script_live_value_refuses_out_of_range_amounts() {
        let coin = ScriptLiveCoin::new(
            ScriptHash::from_byte_array([1; 32]),
            MAX_MONEY + 1,
            0,
            false,
        );
        assert_eq!(
            coin.encode_value(),
            Err(ScriptLiveValueError::AmountOutOfRange {
                value: MAX_MONEY + 1,
            })
        );
        assert_eq!(coin.encoded_value_len(), None);
    }

    // PRJ-11
    proptest! {
    #![proptest_config(proptest::test_runner::Config {
        failure_persistence: Some(std::boxed::Box::new(
            proptest::test_runner::FileFailurePersistence::Direct(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/projection/regressions/script_live.txt"
            )),
        )),
        ..(proptest::test_runner::Config {
            cases: std::env::var("PROPTEST_CASES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1024),
            ..proptest::test_runner::Config::default()
        })
    })]
        #[test]
        fn script_live_value_round_trips_and_refuses_mutation(
            coin in row_codec(),
            cut in 0_usize..76,
            filler in proptest::collection::vec(proptest::arbitrary::any::<u8>(), 1..=8),
        ) {
            let encoded = coin.encode_value().map_err(|error| {
                proptest::test_runner::TestCaseError::fail(format!("encode failed: {error}"))
            })?;
            prop_assert!(encoded.len() >= 33);
            let expected_len = match coin.encoded_value_len() {
                Some(len) => len,
                None => {
                    return Err(proptest::test_runner::TestCaseError::fail(
                        "in-range amount must have an encoded length",
                    ));
                }
            };
            prop_assert_eq!(encoded.len(), expected_len);
            prop_assert_eq!(ScriptLiveCoin::decode_value(&encoded), Ok(coin));

            let cut = cut % encoded.len();
            let truncated = &encoded[..cut];
            prop_assert!(
                ScriptLiveCoin::decode_value(truncated).is_err(),
                "truncated value must be refused"
            );

            let mut overlong = encoded.clone();
            overlong.extend_from_slice(&filler);
            prop_assert_eq!(
                ScriptLiveCoin::decode_value(&overlong),
                Err(ScriptLiveValueError::TrailingBytes)
            );
        }
    }
}
mod segment_recovery {
    use bitcoin_rs_projection::segment::bulk_builder::BulkSegmentBuilder;
    use bitcoin_rs_projection::segment::{
        IndexGeneration, NoSealedTxOrdinals, RetireFault, SealFault, TailWriterState,
        append_tail_block, arm_retire_fault, arm_seal_fault, meta_gen_key, publish_sealed,
        recover_segments, seal_tail_generation,
    };
    use bitcoin_rs_projection::{IndexCapabilities, IndexCapability};
    use bitcoin_rs_storage::budget::UnboundedBudget;
    use bitcoin_rs_storage::committed_facts::{
        CommittedBlock, CreatedOutput, SpentPrevout, TxFacts,
    };
    use bitcoin_rs_storage::{ColumnFamily, FactsScript, KvStore, RocksDbStore};
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
                        script: FactsScript::copy_from_slice(b"\x51recovery_script\x88\xac"),
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
                        script: FactsScript::copy_from_slice(b"\x51recovery_script\x88\xac"),
                        height: 1,
                        coinbase: false,
                    }],
                    outputs: vec![CreatedOutput {
                        vout: 0,
                        value: 3_000,
                        script: FactsScript::copy_from_slice(
                            b"\x76\xa9\x14recovery_second\x88\xac",
                        ),
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

    fn family_rows(
        store: &RocksDbStore,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<usize, TestError> {
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
        SEGMENT_CFS
            .iter()
            .map(|&cf| hash_family(&store, cf, 1).map(|digest| (cf, digest)))
            .collect()
    }

    fn tail_only_store(blocks: &[CommittedBlock]) -> Result<(TempDir, RocksDbStore), TestError> {
        let dir = tempdir()?;
        let store = RocksDbStore::open(dir.path())?;
        let mut state = TailWriterState::new();
        for block in blocks {
            let mut batch = store.new_batch();
            append_tail_block(&mut batch, block, &mut state, &NoSealedTxOrdinals)?;
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
        let sealed = seal_tail_generation(&store, 1, 1, IndexCapabilities::ALL, tempdir()?.path());
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

        let cut = 1u32;
        seal_tail_generation(&store, 1, cut, IndexCapabilities::ALL, tempdir()?.path())?;
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
        let sealed = seal_tail_generation(&store, 1, 1, IndexCapabilities::ALL, tempdir()?.path());
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
        for capability in [
            IndexCapability::TxLookup,
            IndexCapability::ScriptHistory,
            IndexCapability::CompactFilters,
        ] {
            assert!(
                snapshot
                    .get(ColumnFamily::IdxMeta, &meta_gen_key(capability))?
                    .is_some(),
                "{capability:?} descriptor must publish"
            );
        }
        assert!(
            snapshot
                .get(
                    ColumnFamily::IdxMeta,
                    &meta_gen_key(IndexCapability::ScriptLive)
                )?
                .is_none(),
            "ScriptLive keeps no segment descriptor"
        );
        Ok(())
    }

    // PRJ-05
    #[test]
    fn seal_fault_after_tail_clear_recovers_by_completion() -> Result<(), TestError> {
        let blocks = one_spend_generation();
        let (_dir, store) = tail_only_store(&blocks)?;
        arm_seal_fault(Some(SealFault::AfterPublish));
        let sealed = seal_tail_generation(&store, 1, 1, IndexCapabilities::ALL, tempdir()?.path());
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
            append_tail_block(&mut batch, block, &mut state, &NoSealedTxOrdinals)?;
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
            1,
            IndexCapabilities::ALL,
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

    // PRJ-05
    #[test]
    fn seal_publishes_descriptors_only_for_built_capabilities() -> Result<(), TestError> {
        let blocks = one_spend_generation();
        let (_dir, store) = tail_only_store(&blocks)?;

        seal_tail_generation(
            &store,
            1,
            1,
            IndexCapabilities::TX_LOOKUP,
            tempdir()?.path(),
        )?;

        let snapshot = store.snapshot()?;
        assert!(
            snapshot
                .get(
                    ColumnFamily::IdxMeta,
                    &meta_gen_key(IndexCapability::TxLookup)
                )?
                .is_some(),
            "built capability must publish its descriptor"
        );
        assert!(
            snapshot
                .get(
                    ColumnFamily::IdxMeta,
                    &meta_gen_key(IndexCapability::ScriptHistory)
                )?
                .is_none(),
            "unbuilt capability must not publish a descriptor"
        );
        assert!(
            snapshot
                .get(
                    ColumnFamily::IdxMeta,
                    &meta_gen_key(IndexCapability::CompactFilters)
                )?
                .is_none(),
            "unbuilt capability must not publish a descriptor"
        );
        assert!(
            snapshot
                .get(
                    ColumnFamily::IdxMeta,
                    &meta_gen_key(IndexCapability::ScriptLive)
                )?
                .is_none(),
            "ScriptLive keeps no segment descriptor"
        );
        Ok(())
    }

    // REO-04
    #[test]
    fn retire_fault_after_tombstone_recovers_by_completion() -> Result<(), TestError> {
        use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid};
        use bitcoin_rs_projection::types::{ScriptHash, ScriptHistoryOccurrence, TxPositionValue};
        use bitcoin_rs_projection::{IndexReader, Indexer};
        use bitcoin_rs_storage::PrefixScanLimit;

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
        let tx_count: usize = blocks.iter().map(|block| block.txs.len()).sum();
        publish_sealed(
            &store,
            1,
            coverage,
            u32::try_from(tx_count).map_err(|e| e.to_string())?,
            IndexCapabilities::ALL,
        )?;

        arm_retire_fault(Some(RetireFault::AfterTombstone));
        let retired =
            bitcoin_rs_projection::segment::retire_generation(&store, IndexCapability::TxLookup, 1);
        arm_retire_fault(None);
        assert!(retired.is_err(), "injected fault must abort the retire");

        recover_segments(&store)?;
        assert!(
            store
                .snapshot()?
                .get(
                    ColumnFamily::IdxMeta,
                    &bitcoin_rs_projection::segment::sealed_gen_key(IndexCapability::TxLookup, 1),
                )?
                .is_none(),
            "recovery must remove the retired capability's sealed publication"
        );

        let store = Arc::new(store);
        let indexer = Indexer::new(Arc::clone(&store));
        let view = indexer.snapshot()?;
        let limit = PrefixScanLimit {
            max_rows: 16,
            max_bytes: 1 << 20,
        };
        let history = view.funding_rows(
            ScriptHash::from_script_bytes(b"\x51recovery_script\x88\xac"),
            limit,
        )?;
        assert!(history.complete, "surviving history scan must complete");
        let mut occurrences = Vec::new();
        for row in &history.rows {
            for occurrence in ScriptHistoryOccurrence::decode_all(&row.value)
                .ok_or("surviving history must decode")?
            {
                occurrences.push((
                    row.row.height(),
                    occurrence.txid,
                    occurrence.position.offset(),
                    occurrence.position.byte_len(),
                    occurrence.flags,
                ));
            }
        }
        occurrences.sort_unstable();
        assert_eq!(
            occurrences,
            vec![
                (1, [0xE1; 32], 0, 100, ScriptHistoryOccurrence::FUNDING),
                (1, [0xE2; 32], 100, 120, ScriptHistoryOccurrence::SPENDING),
            ],
            "tombstone recovery must preserve the published sibling's funding and spending occurrences"
        );
        let spender = view.spending_rows(
            &OutPoint {
                txid: Txid::from(Hash256::from_le_bytes(&[0xE1; 32])),
                vout: 0,
            },
            limit,
        )?;
        assert!(spender.complete, "surviving spender scan must complete");
        assert_eq!(spender.rows.len(), 1, "the fixture has exactly one spender");
        assert_eq!(spender.rows[0].row.height(), 1);
        assert_eq!(
            TxPositionValue::decode(&spender.rows[0].value).map(|positions| positions
                .iter()
                .map(|position| (position.offset(), position.byte_len()))
                .collect::<Vec<_>>()),
            Some(vec![(100, 120)]),
            "the surviving sibling must resolve the spender's literal byte range"
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
        let descriptor = snapshot.get(
            ColumnFamily::IdxMeta,
            &meta_gen_key(IndexCapability::TxLookup),
        )?;
        assert!(
            descriptor
                .and_then(|bytes| IndexGeneration::decode_meta_value(&bytes))
                .is_none_or(|desc| desc.gen_id == 0),
            "retired descriptor must not name the retired generation"
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
}
mod silent_payments {
    #![cfg(feature = "silent-payments")]

    use crate::test_support_error::TestError;
    use bitcoin::hex::{DisplayHex as _, FromHex as _};
    use bitcoin_hashes::hash160;
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, OutPoint, Script, Tx, TxIn, TxOut, Txid, Witness,
    };
    use bitcoin_rs_projection::silent_payments::{
        MAX_BODY_BYTES, MAX_PREVOUT_BYTES, TransactionTweak, TweakError, block_tweaks,
        transaction_tweak,
    };
    use bitcoin_rs_storage::utxo::{
        UtxoCoin,
        contract::{BlockSpends, BlockSpendsError, HistoryUnavailable},
    };
    use serde::Deserialize;

    type Result<T = ()> = std::result::Result<T, TestError>;

    #[derive(Deserialize)]
    struct Vector {
        comment: String,
        vin: Vec<Input>,
        outputs: Vec<String>,
        expected: Expected,
    }

    #[derive(Deserialize)]
    struct Expected {
        input_pub_key_sum: Option<String>,
        tweak: Option<String>,
    }

    #[derive(Deserialize)]
    struct Input {
        txid: String,
        vout: u32,
        #[serde(rename = "scriptSig")]
        script_sig: String,
        txinwitness: String,
        prevout: Prevout,
    }

    #[derive(Deserialize)]
    struct Prevout {
        #[serde(rename = "scriptPubKey")]
        script: HexScript,
    }

    #[derive(Deserialize)]
    struct HexScript {
        hex: String,
    }

    fn vectors() -> Result<Vec<Vector>> {
        Ok(sonic_rs::from_str(include_str!(
            "../../testdata/projection/data/bip352-public-scan.json"
        ))?)
    }

    fn vector_tx(vector: &Vector) -> Result<(Tx, Vec<Script>)> {
        let mut tx = Tx {
            version: 2,
            ..Tx::default()
        };
        let mut scripts = Vec::new();
        for vin in &vector.vin {
            let witness = if vin.txinwitness.is_empty() {
                Witness::new()
            } else {
                let bytes = Vec::from_hex(&vin.txinwitness)?;
                bitcoin::consensus::deserialize::<bitcoin::Witness>(&bytes)?
                    .to_vec()
                    .into()
            };
            tx.inputs.push(TxIn {
                previous_output: OutPoint::new(vin.txid.parse()?, vin.vout),
                script_sig: Vec::from_hex(&vin.script_sig)?.into(),
                witness,
                ..TxIn::default()
            });
            scripts.push(Vec::from_hex(&vin.prevout.script.hex)?.into());
        }
        for output in &vector.outputs {
            let mut script = vec![0x51, 0x20];
            script.extend_from_slice(&Vec::from_hex(output)?);
            tx.outputs.push(TxOut {
                script_pubkey: script.into(),
                value: Amount::from_sat(0),
            });
        }
        if tx.outputs.is_empty() {
            tx.outputs.push(TxOut {
                script_pubkey: [vec![0x51, 0x20], vec![0x11; 32]].concat().into(),
                ..TxOut::default()
            });
        }
        Ok((tx, scripts))
    }

    fn derive(tx: &Tx, scripts: &[Script]) -> Result<Option<TransactionTweak>> {
        Ok(transaction_tweak(
            tx,
            &scripts.iter().map(Some).collect::<Vec<_>>(),
            true,
        )?)
    }

    fn sample() -> Result<(Tx, Vec<Script>, TransactionTweak)> {
        let cases = vectors()?;
        let (tx, scripts) = vector_tx(&cases[0])?;
        let tweak = derive(&tx, &scripts)?.ok_or("sample is eligible")?;
        Ok((tx, scripts, tweak))
    }

    #[test]
    fn pinned_bip352_public_vectors() -> Result {
        let cases = vectors()?;
        assert_eq!(cases.len(), 29);
        for case in cases {
            let (tx, scripts) = vector_tx(&case)?;
            let material = derive(&tx, &scripts)?;
            match case.expected.tweak {
                Some(expected) => {
                    let material =
                        material.ok_or_else(|| format!("{} was skipped", case.comment))?;
                    assert_eq!(
                        material.tweak.to_lower_hex_string(),
                        expected,
                        "{}",
                        case.comment
                    );
                    assert_eq!(
                        Some(material.input_public_key_sum.to_lower_hex_string()),
                        case.expected.input_pub_key_sum,
                        "{}",
                        case.comment
                    );
                    assert_eq!(
                        material.outputs.len(),
                        case.outputs.len(),
                        "{}",
                        case.comment
                    );
                    for (candidate, output) in material.outputs.iter().zip(&case.outputs) {
                        assert_eq!(candidate.output_key.to_lower_hex_string(), *output);
                    }
                    assert_eq!(material.txid, tx.txid());
                }
                None => assert!(material.is_none(), "{}", case.comment),
            }
        }
        Ok(())
    }

    #[test]
    fn missing_prevouts_never_become_empty_success() -> Result {
        let (mut tx, scripts, _) = sample()?;
        assert_eq!(
            transaction_tweak(&tx, &[], true),
            Err(TweakError::PrevoutCount)
        );
        assert_eq!(
            transaction_tweak(&tx, &[Some(&scripts[0]), None], true),
            Err(TweakError::Unavailable { input: 1 })
        );
        tx.outputs.clear();
        assert_eq!(
            transaction_tweak(&tx, &[Some(&scripts[0]), None], true),
            Err(TweakError::Unavailable { input: 1 })
        );
        assert!(derive(&tx, &scripts)?.is_none());
        Ok(())
    }

    fn p2sh_script(redeem_script: &[u8]) -> Script {
        let hash = hash160::Hash::hash(redeem_script);
        let mut script = Vec::with_capacity(23);
        script.extend_from_slice(&[0xa9, 0x14]);
        script.extend_from_slice(hash.as_byte_array());
        script.push(0x87);
        script.into()
    }

    #[test]
    fn future_witness_excludes_transaction_but_malformed_program_does_not() -> Result {
        let (mut tx, mut scripts, initial) = sample()?;
        let mut last_p2sh_script = None;
        for len in [2_u8, 20, 32, 40] {
            for version in [0x52, 0x60] {
                let future_prog = [vec![version, len], vec![0x11; usize::from(len)]].concat();
                scripts[1] = future_prog.clone().into();
                assert!(derive(&tx, &scripts)?.is_none());

                tx.inputs[1].script_sig = [vec![len + 2], future_prog.clone()].concat().into();
                let p2sh = p2sh_script(&future_prog);
                scripts[1] = p2sh.clone();
                let p2sh_derived = derive(&tx, &scripts)?.ok_or("eligible via input 0")?;
                assert_eq!(p2sh_derived.outputs.len(), initial.outputs.len());
                last_p2sh_script = Some(p2sh);
            }
        }
        let p2sh_script = last_p2sh_script.ok_or("p2sh script")?;

        let mut malformed_scripts = scripts.clone();
        malformed_scripts[1] = vec![0x52, 0x20, 0x11].into();
        assert!(derive(&tx, &malformed_scripts)?.is_some());

        let single_input_tx = Tx {
            version: 2,
            inputs: vec![tx.inputs[1].clone()],
            outputs: tx.outputs.clone(),
            ..Tx::default()
        };
        assert!(derive(&single_input_tx, &[p2sh_script])?.is_none());
        Ok(())
    }

    #[test]
    fn lowest_outpoint_includes_ineligible_inputs_and_uses_wire_order() -> Result {
        let (mut tx, mut scripts, _) = sample()?;
        tx.inputs.push(TxIn {
            previous_output: OutPoint::new(Txid::default(), 256),
            ..TxIn::default()
        });
        scripts.push(vec![0x51].into());
        let first = derive(&tx, &scripts)?.ok_or("eligible")?;
        tx.inputs[2].previous_output = OutPoint::new(Txid::default(), 1);
        let second = derive(&tx, &scripts)?.ok_or("eligible")?;
        assert_eq!(first.input_public_key_sum, second.input_public_key_sum);
        assert_ne!(first.input_hash, second.input_hash);
        tx.inputs.reverse();
        scripts.reverse();
        assert_eq!(
            derive(&tx, &scripts)?.ok_or("eligible")?.tweak,
            second.tweak
        );
        Ok(())
    }

    #[test]
    fn taproot_annex_and_script_path_nums_are_handled_without_mutation() -> Result {
        let cases = vectors()?;
        let case = cases
            .iter()
            .find(|case| case.comment == "Single recipient: taproot only inputs with even y-values")
            .ok_or("taproot vector")?;
        let (mut tx, scripts) = vector_tx(case)?;
        let initial = derive(&tx, &scripts)?.ok_or("eligible")?;
        tx.inputs[0].witness.push(&[0x50, 0x99]);
        assert_eq!(derive(&tx, &scripts)?.ok_or("annex")?.tweak, initial.tweak);
        let before = tx.clone();
        derive(&tx, &scripts)?;
        assert_eq!(tx, before);
        let mut control = vec![0xc0];
        control.extend_from_slice(&Vec::from_hex(
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
        )?);
        tx.inputs[0].witness = vec![vec![0x51], control.clone(), vec![0x50]].into();
        let with_nums = derive(&tx, &scripts)?.ok_or("other input remains")?;
        assert_ne!(with_nums.input_public_key_sum, initial.input_public_key_sum);
        control[1] ^= 1;
        tx.inputs[0].witness = vec![vec![0x51], control, vec![0x50]].into();
        assert_eq!(
            derive(&tx, &scripts)?.ok_or("non-NUMS script path")?.tweak,
            initial.tweak
        );
        tx.inputs[0].witness = vec![vec![0x51], vec![]].into();
        assert!(derive(&tx, &scripts).is_err());
        Ok(())
    }

    #[test]
    fn candidates_keep_indices_duplicates_and_dust_without_wallet_filtering() -> Result {
        let (mut tx, scripts, initial) = sample()?;
        let candidate = tx.outputs[0].clone();
        tx.outputs.insert(
            0,
            TxOut {
                script_pubkey: vec![0x51].into(),
                ..TxOut::default()
            },
        );
        tx.outputs.push(candidate);
        let material = derive(&tx, &scripts)?.ok_or("eligible")?;
        assert_eq!(material.tweak, initial.tweak);
        assert_eq!(material.outputs.len(), 2);
        assert_eq!(material.outputs[0].vout, 1);
        assert_eq!(material.outputs[1].vout, 2);
        assert_eq!(
            material.outputs[0].output_key,
            material.outputs[1].output_key
        );
        Ok(())
    }

    fn view(tx: Tx, scripts: &[Script]) -> BlockSpends {
        let coins = tx
            .inputs
            .iter()
            .zip(scripts)
            .map(|(input, script)| UtxoCoin {
                outpoint: input.previous_output,
                txout: TxOut {
                    script_pubkey: script.clone(),
                    ..TxOut::default()
                },
                coinbase: false,
                height: 1,
            })
            .collect();
        BlockSpends {
            block: Block {
                txs: vec![tx],
                ..Block::default()
            },
            spent: Ok(vec![coins]),
        }
    }

    #[test]
    fn retained_block_projection_is_hash_scoped_and_deterministic() -> Result {
        let (tx, scripts, material) = sample()?;
        let mut view = view(tx, &scripts);
        let first = block_tweaks(&view, true)?;
        assert_eq!(first.transactions, vec![material]);
        assert_eq!(first.hash, view.block.block_hash());
        assert_eq!(block_tweaks(&view, true)?, first);
        view.block.header.nonce ^= 1;
        let replacement = block_tweaks(&view, true)?;
        assert_ne!(replacement.hash, first.hash);
        assert_eq!(replacement.transactions, first.transactions);
        view.block.header.nonce ^= 1;
        assert_eq!(block_tweaks(&view, true)?, first);
        view.spent.as_mut().map_err(|_| "spent")?[0].reverse();
        assert!(matches!(
            block_tweaks(&view, true),
            Err(BlockSpendsError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn incomplete_history_is_typed_even_for_empty_blocks() -> Result {
        let mut view = BlockSpends {
            block: Block::default(),
            spent: Ok(vec![]),
        };
        assert_eq!(
            block_tweaks(&view, true)?.transactions,
            Vec::<TransactionTweak>::new()
        );
        assert_eq!(
            block_tweaks(&view, false)?.transactions,
            Vec::<TransactionTweak>::new()
        );
        for reason in [
            HistoryUnavailable::Missing,
            HistoryUnavailable::Pruned { below: 10 },
            HistoryUnavailable::Reserved { below: 10 },
            HistoryUnavailable::Shutdown,
        ] {
            view.spent = Err(reason);
            assert!(
                matches!(block_tweaks(&view, true), Err(BlockSpendsError::History(actual)) if actual == reason)
            );
            assert!(
                matches!(block_tweaks(&view, false), Err(BlockSpendsError::History(actual)) if actual == reason)
            );
        }
        view.spent = Ok(vec![vec![]]);
        assert!(matches!(
            block_tweaks(&view, true),
            Err(BlockSpendsError::Corrupt(_))
        ));
        Ok(())
    }

    #[test]
    fn materialization_limits_fail_explicitly() -> Result {
        let (mut tx, mut scripts, _) = sample()?;
        scripts[0] = vec![0x51; MAX_PREVOUT_BYTES + 1].into();
        assert!(matches!(
            derive(&tx, &scripts),
            Err(TestError::Tweak(TweakError::ResourceLimit))
        ));
        let oversized_view = view(tx.clone(), &scripts);
        assert!(matches!(
            block_tweaks(&oversized_view, true),
            Err(BlockSpendsError::ResourceLimit)
        ));
        scripts[0] = Script::new();
        tx.outputs[0].script_pubkey = vec![0x51; MAX_BODY_BYTES + 1].into();
        assert!(matches!(
            transaction_tweak(&tx, &[], true),
            Err(TweakError::ResourceLimit)
        ));
        assert!(matches!(
            block_tweaks(&view(tx, &scripts), true),
            Err(BlockSpendsError::ResourceLimit)
        ));
        Ok(())
    }

    #[test]
    fn pre_activation_witness_v1_spends_produce_no_tweaks_without_failing() -> Result {
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), 0),
                witness: Witness::new(),
                ..TxIn::default()
            }],
            outputs: vec![TxOut {
                script_pubkey: [vec![0x51, 0x20], vec![0x33; 32]].concat().into(),
                value: Amount::from_sat(1000),
            }],
            ..Tx::default()
        };
        let v1_prevout: Script = [vec![0x51, 0x20], vec![0x44; 32]].concat().into();
        let scripts = [Some(&v1_prevout)];

        assert_eq!(transaction_tweak(&tx, &scripts, false)?, None);
        let view_inactive = view(tx.clone(), std::slice::from_ref(&v1_prevout));
        let tweaks_inactive = block_tweaks(&view_inactive, false)?;
        assert_eq!(tweaks_inactive.transactions.len(), 0);

        assert_eq!(
            transaction_tweak(&tx, &scripts, true),
            Err(TweakError::InvalidInput { input: 0 })
        );
        let view_active = view(tx, std::slice::from_ref(&v1_prevout));
        assert!(matches!(
            block_tweaks(&view_active, true),
            Err(BlockSpendsError::Corrupt(_))
        ));
        Ok(())
    }
}
mod tail_group_rollback {
    //! The shared tail rolls back as one group. Rolling back `ScriptHistory` at
    //! height `h` moves `TxLookup`, `ScriptHistory`, and `CompactFilters` to `h-1`
    //! together, and the reads those capabilities serve equal a bulk build of the
    //! chain truncated at `h-1`. Re-forwarding `h` restores the bulk build at `h`.

    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::support::TestError;
    use crate::support::common::MemoryStore;
    use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid, encode};
    use bitcoin_rs_projection::segment::bulk_builder::BulkSegmentBuilder;
    use bitcoin_rs_projection::segment::publish_sealed;
    use bitcoin_rs_projection::{
        BasicFilter, ConsumerCursorUpdate, IndexCapabilities, IndexReader, IndexWatermark,
        IndexWriter, Indexer, PreparedBatch, PreparedBatchLimits, ScriptHash, SpentCoin,
        SpentCoins, TxIndexScanRow, TxIndexSnapshot,
    };
    use bitcoin_rs_storage::budget::UnboundedBudget;
    use bitcoin_rs_storage::committed_facts::{
        CommittedBlock, CreatedOutput, SpentPrevout, TxFacts,
    };
    use bitcoin_rs_storage::{FactsScript, PrefixScanLimit, RocksDbStore};

    const BLOCKS: u32 = 3;
    const COINBASE_VALUE: u64 = 50 * 100_000_000;
    const CHILD_VALUE: u64 = COINBASE_VALUE - 1_000;
    const CAPS: IndexCapabilities = IndexCapabilities::HISTORICAL.with_compact_filters(true);
    const SCAN_ALL: PrefixScanLimit = PrefixScanLimit {
        max_rows: 100_000,
        max_bytes: 64 << 20,
    };

    fn script_for(seed: u32) -> Vec<u8> {
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&[0x11; 20]);
        script[2] = u8::try_from(seed % 251).unwrap_or(0);
        script[3] = u8::try_from((seed / 251) % 251).unwrap_or(0);
        script
    }

    struct Coin {
        script: Vec<u8>,
        value: u64,
        height: u32,
        coinbase: bool,
    }

    #[derive(Default)]
    struct Coins {
        by_outpoint: HashMap<([u8; 32], u32), Coin>,
    }

    impl SpentCoins for Coins {
        fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<SpentCoin<'_>> {
            self.by_outpoint.get(&(*txid, vout)).map(|coin| SpentCoin {
                script: &coin.script,
                value: coin.value,
                height: coin.height,
                coinbase: coin.coinbase,
            })
        }
    }

    fn coinbase_coin(height: u32) -> Coin {
        Coin {
            script: script_for(height),
            value: COINBASE_VALUE,
            height,
            coinbase: true,
        }
    }

    fn push_script(out: &mut Vec<u8>, script: &[u8]) {
        out.push(u8::try_from(script.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(script);
    }

    fn coinbase_tx(height: u32) -> Vec<u8> {
        let coin = coinbase_coin(height);
        let mut tx = Vec::new();
        tx.extend_from_slice(&1_u32.to_le_bytes());
        tx.push(0x01);
        tx.extend_from_slice(&[0_u8; 32]);
        tx.extend_from_slice(&u32::MAX.to_le_bytes());
        push_script(&mut tx, &[height.to_le_bytes()[0], 0xFF]);
        tx.extend_from_slice(&u32::MAX.to_le_bytes());
        tx.push(0x01);
        tx.extend_from_slice(&coin.value.to_le_bytes());
        push_script(&mut tx, &coin.script);
        tx.extend_from_slice(&0_u32.to_le_bytes());
        tx
    }

    fn spend_tx(previous: &[u8; 32], script: &[u8]) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&1_u32.to_le_bytes());
        tx.push(0x01);
        tx.extend_from_slice(previous);
        tx.extend_from_slice(&0_u32.to_le_bytes());
        push_script(&mut tx, &[]);
        tx.extend_from_slice(&u32::MAX.to_le_bytes());
        tx.push(0x01);
        tx.extend_from_slice(&CHILD_VALUE.to_le_bytes());
        push_script(&mut tx, script);
        tx.extend_from_slice(&0_u32.to_le_bytes());
        tx
    }

    fn block_body(parent: &[u8; 32], height: u32, txs: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1_i32.to_le_bytes());
        body.extend_from_slice(parent);
        body.extend_from_slice(&[0_u8; 32]);
        body.extend_from_slice(&(1_600_000_000_u32 + height).to_le_bytes());
        body.extend_from_slice(&0x207F_FFFF_u32.to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.push(u8::try_from(txs.len()).unwrap_or(u8::MAX));
        for tx in txs {
            body.extend_from_slice(tx);
        }
        body
    }

    struct Chain {
        bodies: Vec<Vec<u8>>,
        hashes: Vec<[u8; 32]>,
        facts: Vec<CommittedBlock>,
        coins: Coins,
        txids: Vec<[u8; 32]>,
        coinbase_txids: Vec<[u8; 32]>,
    }

    /// Each block is a coinbase plus, from height 1, a spend of the previous
    /// coinbase's output. The committed facts mirror what the writer derives from
    /// each body: the coinbase's null prevout, and the spent coin resolved from
    /// `Coins`.
    fn build_chain() -> Result<Chain, TestError> {
        let mut chain = Chain {
            bodies: Vec::new(),
            hashes: Vec::new(),
            facts: Vec::new(),
            coins: Coins::default(),
            txids: Vec::new(),
            coinbase_txids: Vec::new(),
        };
        let mut parent = [0_u8; 32];
        for height in 0..BLOCKS {
            let coinbase = coinbase_tx(height);
            let coinbase_txid = encode::double_sha256(&coinbase).to_le_bytes();
            let coin = coinbase_coin(height);
            let mut txs = vec![coinbase.clone()];
            let mut tx_facts = vec![TxFacts {
                txid: coinbase_txid,
                offset: 81,
                len: u32::try_from(coinbase.len())?,
                inputs: vec![SpentPrevout {
                    txid: [0; 32],
                    vout: u32::MAX,
                    value: 0,
                    script: FactsScript::default(),
                    height,
                    coinbase: true,
                }],
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: coin.value,
                    script: FactsScript::copy_from_slice(&coin.script),
                }],
            }];
            chain.txids.push(coinbase_txid);
            chain.coinbase_txids.push(coinbase_txid);
            chain.coins.by_outpoint.insert((coinbase_txid, 0), coin);

            if height > 0 {
                let previous = height - 1;
                let previous_txid = chain.coinbase_txids[usize::try_from(previous)?];
                let previous_coin = coinbase_coin(previous);
                let spend_script = script_for(100 + height);
                let spend = spend_tx(&previous_txid, &spend_script);
                let spend_txid = encode::double_sha256(&spend).to_le_bytes();
                tx_facts.push(TxFacts {
                    txid: spend_txid,
                    offset: u32::try_from(81 + coinbase.len())?,
                    len: u32::try_from(spend.len())?,
                    inputs: vec![SpentPrevout {
                        txid: previous_txid,
                        vout: 0,
                        value: previous_coin.value,
                        script: FactsScript::copy_from_slice(&previous_coin.script),
                        height: previous_coin.height,
                        coinbase: previous_coin.coinbase,
                    }],
                    outputs: vec![CreatedOutput {
                        vout: 0,
                        value: CHILD_VALUE,
                        script: FactsScript::copy_from_slice(&spend_script),
                    }],
                });
                chain.txids.push(spend_txid);
                txs.push(spend);
            }

            let body = block_body(&parent, height, &txs);
            let hash = encode::double_sha256(&body[..80]).to_le_bytes();
            let mut header = [0_u8; 80];
            header.copy_from_slice(&body[..80]);
            chain.facts.push(CommittedBlock {
                height,
                hash,
                parent_hash: parent,
                header,
                txs: tx_facts,
            });
            chain.bodies.push(body);
            chain.hashes.push(hash);
            parent = hash;
        }
        Ok(chain)
    }

    fn watched_scripts() -> Vec<Vec<u8>> {
        (0..BLOCKS)
            .map(script_for)
            .chain((1..BLOCKS).map(|height| script_for(100 + height)))
            .collect()
    }

    type Rows = Vec<(u32, Vec<u8>)>;

    #[derive(Debug, PartialEq, Eq)]
    struct Reads {
        funding: Vec<Rows>,
        transactions: Vec<Rows>,
        spending: Vec<Rows>,
        filters: Vec<Option<BasicFilter>>,
    }

    fn rows(scan: Vec<TxIndexScanRow>) -> Rows {
        let mut pairs: Rows = scan
            .into_iter()
            .map(|row| (row.row.height(), row.value))
            .collect();
        pairs.sort();
        pairs
    }

    /// Query-level reads over every family the group serves: `ScriptHistory`
    /// funding rows, `TxLookup` transaction rows (the TxDir ordinals sit in their
    /// values), spend rows, and the compact-filter headers.
    fn read_all(snapshot: &dyn TxIndexSnapshot, chain: &Chain) -> Result<Reads, TestError> {
        let mut reads = Reads {
            funding: Vec::new(),
            transactions: Vec::new(),
            spending: Vec::new(),
            filters: Vec::new(),
        };
        for script in watched_scripts() {
            let scripthash = ScriptHash::from_script_bytes(&script);
            reads
                .funding
                .push(rows(snapshot.funding_rows(scripthash, SCAN_ALL)?.rows));
        }
        for txid in &chain.txids {
            let txid = Txid(Hash256::from_le_bytes(txid));
            reads
                .transactions
                .push(rows(snapshot.transaction_rows(&txid, SCAN_ALL)?.rows));
        }
        for txid in &chain.coinbase_txids {
            let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(txid)), 0);
            reads
                .spending
                .push(rows(snapshot.spending_rows(&outpoint, SCAN_ALL)?.rows));
        }
        for (height, hash) in chain.hashes.iter().enumerate() {
            reads
                .filters
                .push(snapshot.compact_filter(u32::try_from(height)?, hash)?);
        }
        Ok(reads)
    }

    fn live_reads(store: &Arc<MemoryStore>, chain: &Chain) -> Result<Reads, TestError> {
        let indexer = Indexer::new(Arc::clone(store));
        let snapshot = indexer.snapshot()?;
        read_all(&*snapshot, chain)
    }

    fn bulk_reads(blocks: &[CommittedBlock], chain: &Chain) -> Result<Reads, TestError> {
        let bulk_dir = tempfile::tempdir()?;
        let scratch = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(bulk_dir.path())?);
        let coverage = BulkSegmentBuilder::new(
            Arc::new(UnboundedBudget),
            None,
            scratch.path().to_path_buf(),
        )
        .build_and_ingest(store.as_ref(), 1, blocks)
        .map_err(|e| e.to_string())?;
        let tx_count: usize = blocks.iter().map(|block| block.txs.len()).sum();
        publish_sealed(store.as_ref(), 1, coverage, u32::try_from(tx_count)?, CAPS)?;
        let indexer = Indexer::new(store);
        let snapshot = indexer.snapshot()?;
        read_all(&*snapshot, chain)
    }

    fn commit_block(
        writer: &mut IndexWriter<MemoryStore>,
        chain: &Chain,
        index: usize,
    ) -> Result<IndexWatermark, TestError> {
        let height = u32::try_from(index)?;
        let prepared = writer.prepare_block_with_spent_scripts(
            CAPS,
            height,
            chain.hashes[index],
            &chain.bodies[index],
            &chain.coins,
        )?;
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        assert!(
            batch.try_push(prepared).is_ok(),
            "one block per batch is admitted"
        );
        Ok(writer.commit_forward(batch)?)
    }

    fn assert_group_at(
        writer: &IndexWriter<MemoryStore>,
        mark: IndexWatermark,
        stage: &str,
    ) -> Result<(), TestError> {
        let watermarks = writer.watermarks()?;
        assert_eq!(watermarks.tx_lookup, Some(mark), "TxLookup {stage}");
        assert_eq!(
            watermarks.script_history,
            Some(mark),
            "ScriptHistory {stage}"
        );
        assert_eq!(
            watermarks.compact_filters,
            Some(mark),
            "CompactFilters {stage}"
        );
        Ok(())
    }
    // IDX-07
    #[test]
    fn shared_tail_group_rollback_matches_bulk_build() -> Result<(), TestError> {
        let chain = build_chain()?;
        let last = usize::try_from(BLOCKS - 1)?;
        let before_last = IndexWatermark {
            height: BLOCKS - 2,
            hash: chain.hashes[last - 1],
        };
        let tip = IndexWatermark {
            height: BLOCKS - 1,
            hash: chain.hashes[last],
        };

        let store = Arc::new(MemoryStore::default());
        let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
        for index in 0..=last {
            commit_block(&mut writer, &chain, index)?;
        }
        assert_group_at(&writer, tip, "after the chain is committed")?;

        let (fence, _) = writer.fenced_watermarks()?;
        writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            IndexCapabilities::SCRIPT_HISTORY,
            Some(before_last),
            &chain.bodies[last],
            ConsumerCursorUpdate::Keep,
            &chain.coins,
        )?;
        assert_group_at(&writer, before_last, "after a ScriptHistory rollback at h")?;

        let truncated = live_reads(&store, &chain)?;
        assert!(
            truncated.filters[..last].iter().all(Option::is_some),
            "the blocks below h keep their filter headers"
        );
        assert_eq!(
            truncated,
            bulk_reads(&chain.facts[..last], &chain)?,
            "reads at h-1 equal a bulk build of the chain truncated at h-1"
        );

        assert_eq!(commit_block(&mut writer, &chain, last)?, tip);
        assert_group_at(&writer, tip, "after re-forwarding h")?;

        let restored = live_reads(&store, &chain)?;
        assert!(
            restored.transactions.iter().any(|rows| !rows.is_empty()),
            "the fixture indexes transactions"
        );
        assert!(
            restored.filters.iter().all(Option::is_some),
            "every block at h has a filter header"
        );
        assert_eq!(
            restored,
            bulk_reads(&chain.facts, &chain)?,
            "re-forwarded reads, TxDir ordinals and filter headers, equal a bulk build at h"
        );
        Ok(())
    }
}
mod tx_positions {
    #![allow(clippy::expect_used)]

    use crate::support::common;

    use std::collections::BTreeSet;
    use std::sync::Arc;

    use bitcoin_rs_consensus::primitives::{
        Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script,
        Sequence, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes, deserialize,
    };
    use bitcoin_rs_projection::types::{TX_POSITION_SIZE, TxPosition, TxPositionValue, U24_MAX};
    use bitcoin_rs_projection::{
        IndexCapabilities, IndexReader, IndexWriter, Indexer, PreparedBatch, PreparedBatchLimits,
        ScriptHash, SpentCoin, SpentCoins,
    };
    use bitcoin_rs_storage::PrefixScanLimit;
    use proptest::prelude::*;

    use common::MemoryStore;

    struct FixtureScripts;

    static FIXTURE_SPENT_SCRIPT: [u8; 2] = [0x51, 0x01];

    impl SpentCoins for FixtureScripts {
        fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
            Some(SpentCoin {
                script: FIXTURE_SPENT_SCRIPT.as_slice(),
                value: 0,
                height: 0,
                coinbase: false,
            })
        }
    }

    fn commit_block(store: &Arc<MemoryStore>, height: u32, body: &[u8]) {
        let mut writer = IndexWriter::open(Arc::clone(store), 1).expect("open");
        let header = body.get(..80).expect("header present");
        let hash = bitcoin_rs_consensus::primitives::encode::double_sha256(header).to_le_bytes();
        let prepared = writer
            .prepare_block_with_spent_scripts(
                IndexCapabilities::HISTORICAL,
                height,
                hash,
                body,
                &FixtureScripts,
            )
            .expect("prepare");
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        assert!(batch.try_push(prepared).is_ok(), "one block is admitted");
        writer.commit_forward(batch).expect("commit");
    }

    fn header() -> Header {
        Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 7,
            bits: CompactTarget::from_consensus(0),
            nonce: 42,
        }
    }

    fn script(tag: u8) -> Vec<u8> {
        let mut bytes = vec![0x00, 0x14];
        bytes.extend_from_slice(&[tag; 20]);
        bytes
    }

    fn tx_legacy(seed: u8, outputs: Vec<TxOut>) -> Tx {
        tx_with_witness(seed, outputs, Vec::new().into())
    }

    fn tx_witness(seed: u8, outputs: Vec<TxOut>) -> Tx {
        tx_with_witness(seed, outputs, vec![vec![0xab; 71], vec![0xcd; 33]].into())
    }

    fn tx_with_witness(seed: u8, outputs: Vec<TxOut>, witness: Witness) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256::from_le_bytes(&[seed; 32])),
                    vout: u32::from(seed),
                },
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            outputs,
        }
    }

    fn out(script_pubkey: Vec<u8>, sats: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: script_pubkey.into(),
        }
    }

    fn mixed_block() -> Block {
        Block {
            header: header(),
            txs: vec![
                tx_legacy(1, vec![out(script(0x11), 1_000)]),
                tx_witness(2, vec![out(script(0x22), 2_000), out(script(0x11), 3_000)]),
                tx_witness(3, vec![out(script(0x33), 4_000)]),
                tx_legacy(4, vec![out(script(0x44), 5_000), out(vec![0x6a, 0x01], 0)]),
            ],
        }
    }

    const SCAN_ALL: PrefixScanLimit = PrefixScanLimit {
        max_rows: 100_000,
        max_bytes: 64 << 20,
    };

    #[test]
    fn funding_positions_address_the_transactions_that_funded_the_script() {
        let block = mixed_block();
        let bytes = consensus_bytes(&block);

        let store = Arc::new(MemoryStore::default());
        commit_block(&store, 0, &bytes);

        let target = ScriptHash::from_script_bytes(&script(0x11));

        let indexer = Indexer::new(Arc::clone(&store));
        let snapshot = indexer.snapshot().expect("snapshot");
        let scan = snapshot
            .funding_rows(target, SCAN_ALL)
            .expect("funding rows");
        assert!(scan.complete, "funding scan must not truncate");
        let occurrences: Vec<_> = scan
            .rows
            .iter()
            .flat_map(|row| {
                bitcoin_rs_projection::types::ScriptHistoryOccurrence::decode_all(&row.value)
                    .expect("row value decodes")
            })
            .collect();
        let funded: Vec<_> = occurrences
            .iter()
            .filter(|occurrence| {
                occurrence.flags & bitcoin_rs_projection::types::ScriptHistoryOccurrence::FUNDING
                    != 0
            })
            .collect();
        assert_eq!(funded.len(), 2, "two transactions funded this script");

        let mut seen = BTreeSet::new();
        for occurrence in funded {
            let position = occurrence.position;
            let start = usize::try_from(position.offset()).expect("offset fits usize");
            let end =
                usize::try_from(position.end().expect("end fits u32")).expect("end fits usize");
            let decoded: Tx =
                deserialize(&bytes[start..end]).expect("position slices a whole transaction");
            assert_eq!(decoded.txid().as_bytes(), &occurrence.txid);
            seen.insert(decoded.txid());
            assert!(
                decoded
                    .outputs
                    .iter()
                    .any(|o| ScriptHash::from_script_bytes(&o.script_pubkey) == target),
                "position must address a transaction that funded the script"
            );
        }
        assert_eq!(
            seen,
            BTreeSet::from([block.txs[0].txid(), block.txs[1].txid()]),
            "funding positions must name exactly the two transactions that funded the script"
        );
    }

    #[test]
    fn txid_positions_address_their_own_transaction() {
        let block = mixed_block();
        let bytes = consensus_bytes(&block);

        let store = Arc::new(MemoryStore::default());
        commit_block(&store, 0, &bytes);

        let indexer = Indexer::new(Arc::clone(&store));
        let snapshot = indexer.snapshot().expect("snapshot");
        let mut row_count = 0;
        for tx in &block.txs {
            let scan = snapshot
                .transaction_rows(&tx.txid(), SCAN_ALL)
                .expect("transaction rows");
            assert!(scan.complete, "transaction scan must not truncate");
            for row in &scan.rows {
                row_count += 1;
                let positions = TxPositionValue::decode(&row.value).expect("row value decodes");
                for position in positions {
                    let start = usize::try_from(position.offset()).expect("offset fits usize");
                    let end = usize::try_from(position.end().expect("end fits u32"))
                        .expect("end fits usize");
                    let decoded: Tx = deserialize(&bytes[start..end])
                        .expect("position slices a whole transaction");
                    assert_eq!(
                        decoded.txid().as_bytes(),
                        tx.txid().as_bytes(),
                        "position must address the transaction whose txid the row is keyed by"
                    );
                }
            }
        }
        assert_eq!(row_count, block.txs.len());
    }

    fn arb_u24() -> impl Strategy<Value = u32> {
        prop_oneof![
            Just(0),
            Just(1),
            Just(2),
            Just(U24_MAX - 1),
            Just(U24_MAX),
            0..=U24_MAX,
        ]
    }

    proptest! {
    #![proptest_config(proptest::test_runner::Config {
        failure_persistence: Some(std::boxed::Box::new(
            proptest::test_runner::FileFailurePersistence::Direct(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/projection/regressions/tx_positions.txt"
            )),
        )),
        ..(ProptestConfig {
            cases: std::env::var("PROPTEST_CASES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1024),
            ..ProptestConfig::default()
        })
    })]
        #[test]
        fn position_values_round_trip(
            raw in proptest::collection::vec((arb_u24(), arb_u24()), 1..=32),
            extra_len in 1_usize..TX_POSITION_SIZE,
            extra_bytes in proptest::collection::vec(any::<u8>(), TX_POSITION_SIZE..=TX_POSITION_SIZE * 2),
            flip_pos in any::<usize>(),
            flip_mask in 1_u8..=255,
        ) {
            let positions = raw
                .iter()
                .map(|(offset, len)| TxPosition::new(*offset, *len))
                .collect::<Vec<_>>();
            let encoded = TxPositionValue::encode(&positions);
            let decoded = TxPositionValue::decode(&encoded);
            prop_assert_eq!(decoded, Some(positions.as_slice()));

            prop_assert_eq!(TxPositionValue::decode(&[]), None);

            for truncated in 1..encoded.len() {
                if truncated % TX_POSITION_SIZE != 0 {
                    prop_assert_eq!(
                        TxPositionValue::decode(&encoded[..truncated]),
                        None,
                        "truncated length {} must fail to decode",
                        truncated
                    );
                }
            }

            let mut extended = encoded.clone();
            extended.extend_from_slice(&extra_bytes[..extra_len]);
            prop_assert_eq!(
                TxPositionValue::decode(&extended),
                None,
                "extended length {} must fail to decode",
                extended.len()
            );

            let flip_idx = flip_pos % encoded.len();
            let mut flipped = encoded.clone();
            flipped[flip_idx] ^= flip_mask;
            if flipped[flip_idx] != encoded[flip_idx] {
                let res = TxPositionValue::decode(&flipped);
                if let Some(other) = res {
                    prop_assert_ne!(
                        other,
                        positions.as_slice(),
                        "mutated position bytes must not decode to identical positions"
                    );
                    prop_assert_eq!(other.len(), positions.len());
                }
            }
        }
    }
}

mod support {
    pub(crate) mod common {
        #![allow(dead_code)]

        use std::collections::BTreeMap;
        use std::ops::Bound;
        use std::sync::atomic::{AtomicBool, Ordering};

        use bitcoin_rs_projection::{PreparedBatch, PreparedBatchLimits, PreparedBlock};
        use bitcoin_rs_storage::{
            BatchOp, BufferedWriteBatch, ColumnFamily, KvIter, KvSnapshot, KvStore, PrefixScan,
            PrefixScanLimit, StorageError, WriteCondition,
        };
        use parking_lot::RwLock;

        #[derive(Default)]
        pub(crate) struct MemoryStore {
            cfs: RwLock<[BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()]>,
            pub(crate) fail_next_fenced_write: AtomicBool,
        }

        impl MemoryStore {
            pub(crate) fn count(&self, cf: ColumnFamily) -> usize {
                self.cfs.read()[cf.index()].len()
            }

            pub(crate) fn arm_fenced_write_failure(&self) {
                self.fail_next_fenced_write.store(true, Ordering::SeqCst);
            }

            pub(crate) fn rows(&self, cf: ColumnFamily) -> Vec<(Vec<u8>, Vec<u8>)> {
                self.cfs.read()[cf.index()]
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect()
            }
        }

        fn scan_prefix_from(
            rows: &BTreeMap<Vec<u8>, Vec<u8>>,
            prefix: &[u8],
            start: &[u8],
            limit: PrefixScanLimit,
        ) -> PrefixScan {
            let seek = std::cmp::max(start, prefix);
            let mut out = Vec::new();
            let mut bytes = 0_usize;
            for (key, value) in rows.range::<[u8], _>((Bound::Included(seek), Bound::Unbounded)) {
                if !key.starts_with(prefix) {
                    break;
                }
                let accepted = key
                    .len()
                    .checked_add(value.len())
                    .and_then(|row_bytes| bytes.checked_add(row_bytes))
                    .filter(|next_bytes| {
                        out.len() < limit.max_rows
                            && (out.is_empty() || *next_bytes <= limit.max_bytes)
                    });
                let Some(next_bytes) = accepted else {
                    return PrefixScan {
                        rows: out,
                        complete: false,
                    };
                };
                out.push((key.clone(), value.clone()));
                bytes = next_bytes;
            }
            PrefixScan {
                rows: out,
                complete: true,
            }
        }

        fn apply_ops(
            cfs: &mut [BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()],
            ops: Vec<BatchOp>,
        ) {
            for op in ops {
                match op {
                    BatchOp::Put { cf, key, value } => {
                        cfs[cf.index()].insert(key, value.into());
                    }
                    BatchOp::Delete { cf, key } => {
                        cfs[cf.index()].remove(&key);
                    }
                    BatchOp::DeleteRange { cf, start, end } => {
                        let doomed: Vec<Vec<u8>> = cfs[cf.index()]
                            .range(start..end)
                            .map(|(key, _value)| key.clone())
                            .collect();
                        for key in doomed {
                            cfs[cf.index()].remove(&key);
                        }
                    }
                }
            }
        }

        impl KvStore for MemoryStore {
            fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
                let guard = self.cfs.read();
                Ok(guard[cf.index()].get(key).cloned())
            }

            fn iter_prefix<'a>(
                &'a self,
                cf: ColumnFamily,
                prefix: &[u8],
            ) -> Result<KvIter<'a>, StorageError> {
                let guard = self.cfs.read();
                let rows = guard[cf.index()]
                    .iter()
                    .filter(|(key, _value)| key.starts_with(prefix))
                    .map(|(key, value)| Ok((key.clone(), value.clone())))
                    .collect::<Vec<_>>();
                Ok(Box::new(rows.into_iter()))
            }

            fn scan_prefix_from_bounded(
                &self,
                cf: ColumnFamily,
                prefix: &[u8],
                start: &[u8],
                limit: PrefixScanLimit,
            ) -> Result<PrefixScan, StorageError> {
                let guard = self.cfs.read();
                Ok(scan_prefix_from(&guard[cf.index()], prefix, start, limit))
            }

            fn new_batch(&self) -> BufferedWriteBatch {
                BufferedWriteBatch::default()
            }

            fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
                let mut guard = self.cfs.write();
                apply_ops(&mut guard, batch.into_ops());
                Ok(())
            }

            fn write_durable_if(
                &self,
                conditions: &[WriteCondition<'_>],
                batch: BufferedWriteBatch,
            ) -> Result<bool, StorageError> {
                if self.fail_next_fenced_write.swap(false, Ordering::SeqCst) {
                    return Err(StorageError::Backend(
                        "injected fenced write failure".into(),
                    ));
                }
                let mut guard = self.cfs.write();
                let matched = conditions.iter().all(|condition| {
                    let (cf, key) = condition.location();
                    condition.matches(guard[cf.index()].get(key).map(Vec::as_slice))
                });
                if !matched {
                    return Ok(false);
                }
                apply_ops(&mut guard, batch.into_ops());
                Ok(true)
            }

            fn flush(&self) -> Result<(), StorageError> {
                Ok(())
            }

            fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
                let guard = self.cfs.read();
                Ok(Box::new(MemorySnapshot { cfs: guard.clone() }))
            }

            fn arm_persist_fault(&self, _fault: bitcoin_rs_storage::PersistFault) {}

            fn multi_get(
                &self,
                cf: ColumnFamily,
                keys: &[&[u8]],
            ) -> Result<Vec<Option<bitcoin_rs_storage::Bytes>>, StorageError> {
                let guard = self.cfs.read();
                let map = &guard[cf.index()];
                Ok(keys
                    .iter()
                    .map(|k| {
                        map.get(*k)
                            .map(|v| bitcoin_rs_storage::Bytes::copy_from_slice(v))
                    })
                    .collect())
            }

            fn ingest_sorted(
                &self,
                cf: ColumnFamily,
                rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
                _scratch: &std::path::Path,
            ) -> Result<u64, StorageError> {
                let mut count = 0u64;
                let mut prev_key: Option<Vec<u8>> = None;
                let mut to_insert = Vec::new();
                for (k, v) in rows {
                    if let Some(prev) = &prev_key {
                        if k.as_slice() <= prev.as_slice() {
                            return Err(StorageError::InvalidOperation(
                                "keys not strictly ascending",
                            ));
                        }
                    }
                    prev_key = Some(k.clone());
                    to_insert.push((k, v));
                    count += 1;
                }
                let mut guard = self.cfs.write();
                let map = &mut guard[cf.index()];
                for (k, v) in to_insert {
                    map.insert(k, v);
                }
                Ok(count)
            }

            fn delete_range(
                &self,
                cf: ColumnFamily,
                start: &[u8],
                end: &[u8],
            ) -> Result<(), StorageError> {
                let mut guard = self.cfs.write();
                let map = &mut guard[cf.index()];
                map.retain(|k, _| k.as_slice() < start || k.as_slice() >= end);
                Ok(())
            }

            fn checkpoint(&self, dir: &std::path::Path) -> Result<(), StorageError> {
                std::fs::create_dir_all(dir).map_err(StorageError::Io)
            }

            fn engine_cache_bytes(&self) -> u64 {
                0
            }
        }

        pub(crate) struct MemorySnapshot {
            cfs: [BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()],
        }

        impl KvSnapshot for MemorySnapshot {
            fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
                Ok(self.cfs[cf.index()].get(key).cloned())
            }

            fn iter_prefix<'a>(
                &'a self,
                cf: ColumnFamily,
                prefix: &[u8],
            ) -> Result<KvIter<'a>, StorageError> {
                let rows = self.cfs[cf.index()]
                    .iter()
                    .filter(|(key, _value)| key.starts_with(prefix))
                    .map(|(key, value)| Ok((key.clone(), value.clone())))
                    .collect::<Vec<_>>();
                Ok(Box::new(rows.into_iter()))
            }

            fn scan_prefix_from_bounded(
                &self,
                cf: ColumnFamily,
                prefix: &[u8],
                start: &[u8],
                limit: PrefixScanLimit,
            ) -> Result<PrefixScan, StorageError> {
                Ok(scan_prefix_from(
                    &self.cfs[cf.index()],
                    prefix,
                    start,
                    limit,
                ))
            }
        }

        pub(crate) fn single_block_batch(block: PreparedBlock) -> PreparedBatch {
            batch_with_limits(
                block,
                PreparedBatchLimits {
                    max_rows: 100,
                    max_bytes: 1_000_000,
                },
            )
        }

        pub(crate) fn batch_with_limits(
            block: PreparedBlock,
            limits: PreparedBatchLimits,
        ) -> PreparedBatch {
            let mut prepared = PreparedBatch::new(limits);
            assert!(
                prepared.try_push(block).is_ok(),
                "batch limits reject the block"
            );
            prepared
        }
    }

    pub(crate) use crate::test_support_error::TestError;
}
