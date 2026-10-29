use super::block::is_op_return_script;
use std::sync::Arc;

use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness, consensus_bytes,
};
use bitcoin_rs_storage::{BufferedWriteBatch, ColumnFamily, KvStore, RocksDbStore};

use super::{IndexCapability, IndexError, IndexReader, IndexWatermark, IndexWriter, Indexer};
use crate::{ScriptHash, ScriptHashRow, ScriptLiveRow, SpendingPrefixRow};

type StoredRows = Vec<(ColumnFamily, Vec<u8>)>;

fn commit_rollback_one<S: KvStore>(
    writer: &mut IndexWriter<S>,
    prev: Option<crate::IndexWatermark>,
    body: &[u8],
) -> Result<(), IndexError> {
    let (fence, _) = writer.fenced_watermarks()?;
    writer.commit_rollback_one_for_with_cursor(
        fence,
        crate::IndexCapabilities::HISTORICAL,
        prev,
        body,
        crate::ConsumerCursorUpdate::Clear,
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
fn iter_funding_rows_returns_indexed_rows() -> Result<(), Box<dyn std::error::Error>> {
    let script = vec![0x51, 0x01];
    let tx = tx(spent_outpoint(1, 0), script.clone());
    let (_dir, mut writer) = writer()?;

    writer.commit_block(0, &consensus_bytes(&block(vec![tx])))?;

    let scripthash = ScriptHash::from_script_bytes(&script);
    assert_eq!(
        writer.indexer().iter_funding_rows(scripthash)?,
        vec![ScriptHashRow::row(scripthash, 0)]
    );
    Ok(())
}

/// Proves that lexicographic key byte order matches numeric height order within one
/// prefix, because the height suffix is big-endian (format 5).
///
/// `[0x00, 0x00, 0x01, 0x00]`, so byte order puts 1 before 256.
#[test]
fn iter_funding_rows_height_order_is_numeric() -> Result<(), Box<dyn std::error::Error>> {
    let script = vec![0x51, 0x01];
    let scripthash = ScriptHash::from_script_bytes(&script);
    let dir = tempfile::tempdir()?;
    let store = Arc::new(RocksDbStore::open(dir.path())?);
    put_funding_row(&store, scripthash, 1)?;
    put_funding_row(&store, scripthash, 256)?;
    let indexer = Indexer::new(store);

    let rows = indexer.iter_funding_rows(scripthash)?;
    assert_eq!(rows.len(), 2, "two heights funded the same script");

    assert_eq!(
        rows.iter().map(|row| row.height()).collect::<Vec<_>>(),
        vec![1, 256],
        "BE byte order matches numeric height order"
    );
    Ok(())
}

#[test]
fn iter_live_outpoints_reports_malformed_row_key_length() -> Result<(), Box<dyn std::error::Error>>
{
    let script = vec![0x51, 0x05];
    let scripthash = ScriptHash::from_script_bytes(&script);
    let dir = tempfile::tempdir()?;
    let store = Arc::new(RocksDbStore::open(dir.path())?);
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;

    let outpoint = spent_outpoint(5, 0);
    writer.seed_script_live(
        [(outpoint, scripthash)],
        IndexWatermark {
            height: 7,
            hash: [0x07; 32],
        },
    )?;

    let mut malformed = ScriptLiveRow::new(scripthash, &outpoint)
        .as_bytes()
        .to_vec();
    malformed.truncate(40);
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::ScriptLive, &malformed, &[]);
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

#[test]
fn iter_spending_rows_returns_indexed_rows() -> Result<(), Box<dyn std::error::Error>> {
    let outpoint = spent_outpoint(2, 3);
    let tx = tx(outpoint, vec![0x51, 0x02]);
    let (_dir, mut writer) = writer()?;

    writer.commit_block(0, &consensus_bytes(&block(vec![tx])))?;

    assert_eq!(
        writer.indexer().iter_spending_rows(&outpoint)?,
        vec![SpendingPrefixRow::row(&outpoint, 0)]
    );
    Ok(())
}

/// A block whose rows populate all four column families: a coinbase plus a
/// spend, so funding and spending rows both exist alongside txid and header
fn rollback_fixture_block() -> Block {
    let funded = tx(OutPoint::null(), vec![0x51]);
    let spender = tx(OutPoint::new(funded.txid(), 0), vec![0x52]);
    block(vec![funded, spender])
}

#[test]
fn rollback_removes_every_row_a_matching_commit_wrote() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut writer) = writer()?;
    let candidate = rollback_fixture_block();
    let body = consensus_bytes(&candidate);
    let before = stored_rows(writer.indexer())?;

    writer.commit_block(0, &body)?;
    let after_commit = stored_rows(writer.indexer())?;
    assert!(
        after_commit.len() > before.len(),
        "fixture must write rows to be a meaningful rollback test"
    );
    for cf in [
        ColumnFamily::TxConfirmed,
        ColumnFamily::Funding,
        ColumnFamily::Spending,
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
fn rollback_without_a_watermark_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
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
-> Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut writer) = writer()?;
    let candidate = rollback_fixture_block();
    let body = consensus_bytes(&candidate);
    writer.commit_block(0, &body)?;
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
}

#[test]
fn rollback_deletes_nothing_when_the_write_fails() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let candidate = rollback_fixture_block();
    let body = consensus_bytes(&candidate);

    {
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let mut writer = IndexWriter::open(store, 1)?;
        writer.commit_block(0, &body)?;
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
-> Result<(), Box<dyn std::error::Error>> {
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
    writer.commit_block(0, &old_body)?;
    commit_rollback_one(&mut writer, None, &old_body)?;
    writer.commit_block(0, &consensus_bytes(&replacement))?;
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
-> Result<(), Box<dyn std::error::Error>> {
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

fn writer() -> Result<(tempfile::TempDir, IndexWriter<RocksDbStore>), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(RocksDbStore::open(dir.path())?);
    Ok((dir, IndexWriter::open(store, 1)?))
}

fn put_funding_row(
    store: &RocksDbStore,
    scripthash: ScriptHash,
    height: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut batch = store.new_batch();
    batch.put(
        ColumnFamily::Funding,
        &ScriptHashRow::row(scripthash, height).to_db_row(),
        &[],
    );
    store.write(batch)?;
    Ok(())
}

fn stored_rows(indexer: &Indexer<RocksDbStore>) -> Result<StoredRows, Box<dyn std::error::Error>> {
    let mut rows = Vec::new();
    for cf in [
        ColumnFamily::TxConfirmed,
        ColumnFamily::Funding,
        ColumnFamily::Spending,
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
