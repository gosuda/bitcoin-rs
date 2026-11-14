use super::block::is_op_return_script;
use std::sync::Arc;

use bitcoin_rs_consensus::primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness, consensus_bytes,
};
use bitcoin_rs_storage::{BufferedWriteBatch, ColumnFamily, KvStore, RocksDbStore};

use super::{
    IndexCapability, IndexError, IndexReader, IndexWatermark, IndexWriter, Indexer, SpentCoins,
};
use crate::segment::tail::PreparedTail;
use crate::{ScriptHash, ScriptLiveRow};

type StoredRows = Vec<(ColumnFamily, Vec<u8>)>;

struct FixtureScripts;

static FIXTURE_SPENT_SCRIPT: [u8; 2] = [0x51, 0x01];

use crate::SpentCoin;

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

fn commit_block<S: KvStore>(
    writer: &mut IndexWriter<S>,
    height: u32,
    body: &[u8],
) -> Result<IndexWatermark, IndexError> {
    let header = body
        .get(..crate::types::HEADER_ROW_SIZE)
        .ok_or(IndexError::InvalidHeaderLength { len: body.len() })?;
    let hash = bitcoin_rs_consensus::primitives::encode::double_sha256(header).to_le_bytes();
    let prepared = writer.prepare_block_with_spent_scripts(
        crate::IndexCapabilities::HISTORICAL,
        height,
        hash,
        body,
        &FixtureScripts,
    )?;
    let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
        max_rows: usize::MAX,
        max_bytes: usize::MAX,
    });
    if batch.try_push(prepared).is_err() {
        return Err(IndexError::NonContiguousPrepared {
            watermark: writer.watermark()?,
        });
    }
    writer.commit_forward(batch)
}

fn commit_rollback_one<S: KvStore>(
    writer: &mut IndexWriter<S>,
    prev: Option<crate::IndexWatermark>,
    body: &[u8],
) -> Result<(), IndexError> {
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
        fence,
        crate::IndexCapabilities::HISTORICAL,
        prev,
        body,
        crate::ConsumerCursorUpdate::Clear,
        &FixtureScripts,
    )
}

#[test]
fn raw_op_return_check_matches_script_prefix_semantics() {
    assert!(!is_op_return_script(&[]));
    assert!(is_op_return_script(&[0x6a]));
    assert!(is_op_return_script(&[0x6a, 0x01, 0x00]));
    assert!(!is_op_return_script(&[0x00, 0x6a]));
}

#[test]
fn iter_live_outpoints_reports_malformed_row_key_length() -> Result<(), crate::portable::TestError>
{
    let script = vec![0x51, 0x05];
    let scripthash = ScriptHash::from_script_bytes(&script);
    let dir = tempfile::tempdir()?;
    let store = Arc::new(RocksDbStore::open(dir.path())?);
    let writer = IndexWriter::open(Arc::clone(&store), 1)?;

    let outpoint = spent_outpoint(5, 0);
    let row = crate::types::ScriptLiveRow::new(scripthash, &outpoint);
    let coin = crate::types::ScriptLiveCoin::new(scripthash, 1_000, 1, false);
    let mut bytes = row.as_bytes().to_vec();
    bytes.extend_from_slice(&coin.encode_value()?);
    let rows = [bytes];
    writer.stage_script_live_rows(&mut rows.into_iter())?;
    let bare_43 = crate::types::ScriptLiveRow::new(scripthash, &outpoint)
        .as_bytes()
        .to_vec();
    assert_eq!(bare_43.len(), 43);
    assert!(matches!(
        writer.stage_script_live_rows(&mut [bare_43].into_iter()),
        Err(IndexError::InvalidLiveRowValue { len: 43 })
    ));
    writer.publish_script_live_seed(IndexWatermark {
        height: 7,
        hash: [0x07; 32],
    })?;

    let mut malformed = ScriptLiveRow::new(scripthash, &outpoint)
        .as_bytes()
        .to_vec();
    malformed.truncate(40);
    let coin = crate::types::ScriptLiveCoin::new(scripthash, 1000, 1, false);
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::ScriptLive, &malformed, &coin.encode_value()?);
    store.write(batch)?;

    let Err(error) = writer.indexer().iter_live_outpoints(scripthash) else {
        return Err(std::io::Error::other("malformed live-row key must fail").into());
    };
    assert!(
        matches!(error, IndexError::InvalidPrefixRowLength { len: 40 }),
        "malformed live-row key must report its length: {error:?}"
    );
    Ok(())
}

fn rollback_fixture_block() -> Block {
    let funded = tx(OutPoint::null(), vec![0x51]);
    let spender = tx(OutPoint::new(funded.txid(), 0), vec![0x52]);
    block(vec![funded, spender])
}

#[test]
fn rollback_removes_every_row_a_matching_commit_wrote() -> Result<(), crate::portable::TestError> {
    let (_dir, mut writer) = writer()?;
    let candidate = rollback_fixture_block();
    let body = consensus_bytes(&candidate);
    let before = stored_rows(writer.indexer())?;

    commit_block(&mut writer, 0, &body)?;
    let after_commit = stored_rows(writer.indexer())?;
    assert!(
        after_commit.len() > before.len(),
        "fixture must write rows to be a meaningful rollback test"
    );
    for cf in [
        ColumnFamily::TxDir,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::BlockHeaders,
    ] {
        assert!(
            after_commit.iter().any(|(family, _)| *family == cf),
            "fixture wrote no rows to {cf:?}"
        );
    }

    commit_rollback_one(&mut writer, None, &body)?;
    assert_eq!(
        stored_rows(writer.indexer())?,
        before,
        "rollback must restore the pre-commit row set exactly"
    );
    Ok(())
}

#[test]
fn rollback_without_a_watermark_is_rejected() -> Result<(), crate::portable::TestError> {
    let (_dir, mut writer) = writer()?;
    let candidate = rollback_fixture_block();
    let body = consensus_bytes(&candidate);

    assert!(matches!(
        commit_rollback_one(&mut writer, None, &body),
        Err(IndexError::NonContiguousPrepared { watermark: None })
    ));
    assert_eq!(stored_rows(writer.indexer())?, Vec::new());
    Ok(())
}

#[test]
fn a_second_rollback_is_rejected_once_the_watermark_is_gone()
-> Result<(), crate::portable::TestError> {
    let (_dir, mut writer) = writer()?;
    let candidate = rollback_fixture_block();
    let body = consensus_bytes(&candidate);
    commit_block(&mut writer, 0, &body)?;
    commit_rollback_one(&mut writer, None, &body)?;
    let after_first = stored_rows(writer.indexer())?;

    assert!(matches!(
        commit_rollback_one(&mut writer, None, &body),
        Err(IndexError::NonContiguousPrepared { watermark: None })
    ));
    assert_eq!(
        stored_rows(writer.indexer())?,
        after_first,
        "a rejected second rollback must be observationally inert"
    );
    Ok(())
}

struct FailingWriteStore(RocksDbStore);

impl bitcoin_rs_storage::KvStore for FailingWriteStore {
    fn get(
        &self,
        cf: ColumnFamily,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
        self.0.get(cf, key)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<bitcoin_rs_storage::KvIter<'a>, bitcoin_rs_storage::StorageError> {
        self.0.iter_prefix(cf, prefix)
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: bitcoin_rs_storage::PrefixScanLimit,
    ) -> Result<bitcoin_rs_storage::PrefixScan, bitcoin_rs_storage::StorageError> {
        self.0.scan_prefix_from_bounded(cf, prefix, start, limit)
    }

    fn new_batch(&self) -> BufferedWriteBatch {
        self.0.new_batch()
    }

    fn write(&self, _batch: BufferedWriteBatch) -> Result<(), bitcoin_rs_storage::StorageError> {
        Err(bitcoin_rs_storage::StorageError::Backend(
            "injected write failure".to_owned(),
        ))
    }

    fn write_durable_if(
        &self,
        _conditions: &[bitcoin_rs_storage::WriteCondition<'_>],
        _batch: BufferedWriteBatch,
    ) -> Result<bool, bitcoin_rs_storage::StorageError> {
        Err(bitcoin_rs_storage::StorageError::Backend(
            "injected write failure".to_owned(),
        ))
    }

    fn flush(&self) -> Result<(), bitcoin_rs_storage::StorageError> {
        self.0.flush()
    }

    fn arm_persist_fault(&self, fault: bitcoin_rs_storage::PersistFault) {
        self.0.arm_persist_fault(fault);
    }

    fn snapshot(
        &self,
    ) -> Result<Box<dyn bitcoin_rs_storage::KvSnapshot + '_>, bitcoin_rs_storage::StorageError>
    {
        self.0.snapshot()
    }

    fn multi_get(
        &self,
        cf: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<bitcoin_rs_storage::Bytes>>, bitcoin_rs_storage::StorageError> {
        self.0.multi_get(cf, keys)
    }

    fn ingest_sorted(
        &self,
        _cf: ColumnFamily,
        _rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        _scratch: &std::path::Path,
    ) -> Result<u64, bitcoin_rs_storage::StorageError> {
        Err(bitcoin_rs_storage::StorageError::Backend(
            "injected write failure".to_owned(),
        ))
    }

    fn delete_range(
        &self,
        _cf: ColumnFamily,
        _start: &[u8],
        _end: &[u8],
    ) -> Result<(), bitcoin_rs_storage::StorageError> {
        Err(bitcoin_rs_storage::StorageError::Backend(
            "injected write failure".to_owned(),
        ))
    }

    fn checkpoint(&self, dir: &std::path::Path) -> Result<(), bitcoin_rs_storage::StorageError> {
        self.0.checkpoint(dir)
    }

    fn engine_cache_bytes(&self) -> u64 {
        self.0.engine_cache_bytes()
    }
}

#[test]
fn rollback_deletes_nothing_when_the_write_fails() -> Result<(), crate::portable::TestError> {
    let dir = tempfile::tempdir()?;
    let candidate = rollback_fixture_block();
    let body = consensus_bytes(&candidate);

    {
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let mut writer = IndexWriter::open(store, 1)?;
        commit_block(&mut writer, 0, &body)?;
    }
    let store = Arc::new(RocksDbStore::open(dir.path())?);
    let before = stored_rows(&Indexer::new(Arc::clone(&store)))?;
    assert!(!before.is_empty(), "fixture must have rows to preserve");
    drop(store);

    let failing = Arc::new(FailingWriteStore(RocksDbStore::open(dir.path())?));
    let mut writer = IndexWriter::open(Arc::clone(&failing), 1)?;
    let outcome = commit_rollback_one(&mut writer, None, &body);
    assert!(outcome.is_err(), "a failing write must surface as an error");
    drop(writer);
    drop(failing);

    let reopened = Indexer::new(Arc::new(RocksDbStore::open(dir.path())?));
    assert_eq!(
        stored_rows(&reopened)?,
        before,
        "a failed rollback must leave every row in place"
    );
    Ok(())
}

#[test]
fn a_stale_rollback_body_leaves_a_replacement_blocks_rows_alone()
-> Result<(), crate::portable::TestError> {
    let (_dir, mut writer) = writer()?;
    let shared_script = vec![0x51];

    let mut old_block = block(vec![tx(
        OutPoint::new(Txid(Hash256::from_le_bytes(&[0xa1; 32])), 0),
        shared_script.clone(),
    )]);
    old_block.header.nonce = 1;
    let mut replacement = block(vec![tx(
        OutPoint::new(Txid(Hash256::from_le_bytes(&[0xb2; 32])), 0),
        shared_script,
    )]);
    replacement.header.nonce = 2;
    assert_ne!(
        old_block.block_hash(),
        replacement.block_hash(),
        "the two blocks must differ, or there is nothing to confuse"
    );

    let old_body = consensus_bytes(&old_block);
    commit_block(&mut writer, 0, &old_body)?;
    commit_rollback_one(&mut writer, None, &old_body)?;
    commit_block(&mut writer, 0, &consensus_bytes(&replacement))?;
    writer.indexer.store.flush()?;
    let after_replacement = stored_rows(writer.indexer())?;
    assert!(
        !after_replacement.is_empty(),
        "the replacement must have written rows"
    );

    assert!(
        commit_rollback_one(&mut writer, None, &old_body).is_err(),
        "rolling back the old body against the replacement watermark must fail"
    );
    writer.indexer.store.flush()?;

    assert_eq!(
        stored_rows(writer.indexer())?,
        after_replacement,
        "a stale rollback body must not touch the replacement's rows"
    );
    Ok(())
}

#[test]
fn anchor_watermark_stamps_a_coverage_floor_that_reset_clears()
-> Result<(), crate::portable::TestError> {
    let (_dir, writer) = writer()?;
    let anchor = IndexWatermark {
        height: 41,
        hash: [7u8; 32],
    };
    writer.anchor_watermark(crate::IndexCapabilities::TX_LOOKUP, anchor, 42)?;

    let snapshot = writer.indexer().snapshot()?;
    assert_eq!(
        snapshot.capability_floor(IndexCapability::TxLookup)?,
        42,
        "anchor records the first covered height"
    );
    assert_eq!(
        snapshot.capability_watermark(IndexCapability::TxLookup)?,
        Some(anchor)
    );
    assert_eq!(
        snapshot.capability_floor(IndexCapability::ScriptHistory)?,
        0,
        "unselected capabilities keep complete coverage"
    );
    drop(snapshot);

    writer.reset_capabilities(crate::IndexCapabilities::TX_LOOKUP)?;
    let snapshot = writer.indexer().snapshot()?;
    assert_eq!(
        snapshot.capability_floor(IndexCapability::TxLookup)?,
        0,
        "a reset rebuilds from genesis, so the floor clears"
    );
    Ok(())
}

fn writer() -> Result<(tempfile::TempDir, IndexWriter<RocksDbStore>), crate::portable::TestError> {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(RocksDbStore::open(dir.path())?);
    Ok((dir, IndexWriter::open(store, 1)?))
}

fn stored_rows(indexer: &Indexer<RocksDbStore>) -> Result<StoredRows, crate::portable::TestError> {
    let mut rows = Vec::new();
    for cf in [
        ColumnFamily::TxDir,
        ColumnFamily::ScriptPost,
        ColumnFamily::SpendDir,
        ColumnFamily::ScriptLive,
        ColumnFamily::BlockHeaders,
    ] {
        for row in indexer.store.iter_prefix(cf, &[])? {
            let (key, _value) = row?;
            rows.push((cf, key));
        }
    }
    rows.sort_by(|left, right| {
        (left.0.name(), left.1.as_slice()).cmp(&(right.0.name(), right.1.as_slice()))
    });
    Ok(rows)
}

fn block(txs: Vec<Tx>) -> Block {
    Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txs,
    }
}

fn tx(previous_output: OutPoint, script_pubkey: Vec<u8>) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(5_000),
            script_pubkey: script_pubkey.into(),
        }],
    }
}

fn spent_outpoint(label: u8, vout: u32) -> OutPoint {
    OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), vout)
}

fn tx_occurrences(first: u8, count: u8) -> Vec<crate::segment::import::TxOccurrence> {
    (0..count)
        .map(|i| crate::segment::import::TxOccurrence {
            txid: [first + i; 32],
            height: 1,
            block_hash: [0x77; 32],
            position: crate::types::TxPosition::new(u32::from(i) * 100, 100),
        })
        .collect()
}

fn tx_dir_rows(store: &RocksDbStore) -> Result<StoredRows, IndexError> {
    let snapshot = store.snapshot()?;
    snapshot
        .iter_prefix(ColumnFamily::TxDir, &[])?
        .map(|row| row.map(|(key, value)| (ColumnFamily::TxDir, [key, value].concat())))
        .collect::<Result<_, _>>()
        .map_err(IndexError::Storage)
}

// IDX-05
#[test]
fn restart_clears_a_staged_segment_and_keeps_the_published_one()
-> Result<(), crate::portable::TestError> {
    let dir = tempfile::tempdir()?;
    let scratch = tempfile::tempdir()?;
    let store = Arc::new(RocksDbStore::open(dir.path())?);
    let base = IndexWatermark {
        height: 1,
        hash: [0x77; 32],
    };
    let coverage = crate::segment::Coverage::new(0, base.height, base.hash);
    let published =
        crate::segment::import::tx_lookup_segment(tx_occurrences(0x10, 3), coverage, 0)?;
    let writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let attachment = crate::writer::TxLookupAttachment {
        headers: &[],
        base,
        floor: 0,
        scratch: scratch.path(),
    };
    writer.attach_tx_lookup_segment(&published, &attachment)?;
    let published_rows = tx_dir_rows(&store)?;
    assert!(!published_rows.is_empty(), "the attach must publish rows");

    let staged = crate::segment::import::tx_lookup_segment(tx_occurrences(0x40, 2), coverage, 3)?;
    let pending = crate::segment::import::next_segment_id(store.as_ref())?;
    crate::segment::import::stage_segment(store.as_ref(), pending, &staged, scratch.path())?;
    assert!(
        tx_dir_rows(&store)?.len() > published_rows.len(),
        "the interrupted stage must leave rows on disk"
    );

    drop(writer);
    let reopened = IndexWriter::open(Arc::clone(&store), 2)?;
    assert_eq!(
        tx_dir_rows(&store)?,
        published_rows,
        "restart must clear the staged rows and leave the published segment unchanged"
    );
    let snapshot = reopened.indexer().snapshot()?;
    assert_eq!(
        snapshot.capability_watermark(IndexCapability::TxLookup)?,
        Some(base)
    );
    let bulk_dir = tempfile::tempdir()?;
    let bulk_store = RocksDbStore::open(bulk_dir.path())?;
    let block = bitcoin_rs_storage::committed_facts::CommittedBlock {
        height: 1,
        hash: [0x77; 32],
        parent_hash: [0; 32],
        header: [0; 80],
        txs: (0..3_u8)
            .map(|i| bitcoin_rs_storage::committed_facts::TxFacts {
                txid: [0x10 + i; 32],
                offset: u32::from(i) * 100,
                len: 100,
                inputs: Vec::new(),
                outputs: Vec::new(),
            })
            .collect(),
    };
    crate::segment::bulk_builder::BulkSegmentBuilder::new(
        Arc::new(bitcoin_rs_storage::budget::UnboundedBudget),
        None,
        scratch.path().to_path_buf(),
    )
    .build_and_ingest(&bulk_store, 1, std::slice::from_ref(&block))
    .map_err(|error| std::io::Error::other(format!("bulk build: {error}")))?;
    assert_eq!(
        tx_dir_rows(&store)?,
        tx_dir_rows(&bulk_store)?,
        "the restored published segment equals a separate bulk build"
    );
    Ok(())
}

// PRJ-06
#[test]
fn a_spend_of_an_output_sealed_under_the_other_capability_resolves_its_creation()
-> Result<(), crate::portable::TestError> {
    use crate::segment::format::{
        TX_KIND_TXID, decode_tx_dir_key, decode_tx_dir_value, encode_spend_dir_key,
        tx_dir_kind_prefix,
    };
    use bitcoin_rs_storage::committed_facts::{
        CommittedBlock, CreatedOutput, SpentPrevout, TxFacts,
    };

    let dir = tempfile::tempdir()?;
    let scratch = tempfile::tempdir()?;
    let store = Arc::new(RocksDbStore::open(dir.path())?);
    let created = CommittedBlock {
        height: 1,
        hash: [1; 32],
        parent_hash: [0; 32],
        header: [0; 80],
        txs: vec![TxFacts {
            txid: [0xA1; 32],
            offset: 0,
            len: 100,
            inputs: Vec::new(),
            outputs: vec![CreatedOutput {
                vout: 0,
                value: 5_000,
                script: bitcoin_rs_storage::Bytes::from_static(b"\x51creator"),
            }],
        }],
    };
    let spending = CommittedBlock {
        height: 2,
        hash: [2; 32],
        parent_hash: [1; 32],
        header: [0; 80],
        txs: vec![TxFacts {
            txid: [0xB2; 32],
            offset: 0,
            len: 100,
            inputs: vec![SpentPrevout {
                txid: [0xA1; 32],
                vout: 0,
                value: 5_000,
                script: bitcoin_rs_storage::Bytes::from_static(b"\x51creator"),
                height: 1,
                coinbase: false,
            }],
            outputs: Vec::new(),
        }],
    };

    let mut state = crate::segment::TailWriterState::new();
    let mut batch = store.new_batch();
    batch.put(
        ColumnFamily::UtxoMeta,
        crate::types::INDEX_FORMAT_VERSION_KEY,
        &crate::types::INDEX_FORMAT_VERSION_VALUE,
    );
    crate::segment::append_tail_block(
        &mut batch,
        &created,
        &mut state,
        &crate::segment::NoSealedTxOrdinals,
    )?;
    store.write_durable(batch)?;
    crate::segment::seal_tail_generation(
        store.as_ref(),
        1,
        1,
        crate::IndexCapabilities::SCRIPT_HISTORY,
        scratch.path(),
    )?;

    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let mut tail = writer.tail_for(None)?;
    let mut batch = store.new_batch();
    let prepared = PreparedTail::new_gated(&spending, true, true);
    writer.append_forward_tail(&mut tail, &[(spending, prepared)], &mut batch)?;
    store.write_durable(batch)?;

    let snapshot = store.snapshot()?;
    let mut creation = None;
    let txid_rows = tx_dir_kind_prefix(1, TX_KIND_TXID);
    for row in snapshot.iter_prefix(ColumnFamily::TxDir, &txid_rows)? {
        let (key, value) = row?;
        let (_, txid, _) = decode_tx_dir_key(&key).ok_or("tx directory key")?;
        if txid == [0xA1; 32] {
            let (_, ordinal, _, _) = decode_tx_dir_value(&value).ok_or("tx directory value")?;
            creation = Some(ordinal);
        }
    }
    let creation = creation.ok_or("the sealed generation names the creating transaction")?;
    assert_eq!(creation, 0, "the first sealed transaction has ordinal zero");
    let spends: Vec<_> = snapshot
        .iter_prefix(ColumnFamily::SpendDir, &0_u64.to_be_bytes())?
        .collect::<Result<_, _>>()?;
    let expected_key = encode_spend_dir_key(0, 0, 0);
    assert_eq!(
        spends.len(),
        1,
        "the cross-capability spend writes one spend row"
    );
    assert_eq!(spends[0].0, expected_key.to_vec());
    Ok(())
}
