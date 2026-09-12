use super::block::is_op_return_script;
use std::sync::Arc;

use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, Network, OutPoint, Script,
    Sequence, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes,
};
use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore, WriteBatch};

use super::{BlockSource, IndexError, IndexWriter, Indexer};
use crate::{ScriptHash, ScriptHashRow, ScriptHistoryEntry, SpendingPrefixRow, TxidRow};

type StoredRows = Vec<(ColumnFamily, Vec<u8>)>;

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

/// Proves that lexicographic key byte order does **not** match numeric
/// height order within one prefix, because the height suffix is
/// little-endian. Height 256 is `[0x00, 0x01, 0x00, 0x00]`, height 1 is
/// `[0x01, 0x00, 0x00, 0x00]`, so byte order puts 256 before 1.
///
/// This pins the corrected doc contract on `iter_funding_rows`: callers
/// needing chronological order must sort by numeric height after
/// exact-resolving rows, never rely on store iteration order.
#[test]
fn iter_funding_rows_height_order_is_le_byte_order_not_numeric()
-> Result<(), Box<dyn std::error::Error>> {
    let script = vec![0x51, 0x01];
    let scripthash = ScriptHash::from_script_bytes(&script);
    let dir = tempfile::tempdir()?;
    let store = Arc::new(RocksDbStore::open(dir.path())?);
    put_funding_row(&store, scripthash, 1)?;
    put_funding_row(&store, scripthash, 256)?;
    let indexer = Indexer::new(store);

    let rows = indexer.iter_funding_rows(scripthash)?;
    assert_eq!(rows.len(), 2, "two heights funded the same script");

    // Store iteration order is LE byte order, so 256 precedes 1.
    assert_eq!(
        rows[0].height(),
        256,
        "LE byte order puts height 256 before height 1, not numeric order"
    );
    assert_eq!(rows[1].height(), 1);

    // The corollary: numeric sort produces the opposite order, so no
    // caller may treat raw iteration order as chronological.
    let mut numeric = rows.clone();
    numeric.sort_by_key(|row| row.height());
    assert_eq!(
        numeric.iter().map(|row| row.height()).collect::<Vec<_>>(),
        vec![1, 256]
    );
    assert_ne!(
        rows, numeric,
        "store iteration order must differ from numeric height order"
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

#[test]
fn iter_txid_rows_returns_indexed_rows() -> Result<(), Box<dyn std::error::Error>> {
    let tx = tx(spent_outpoint(4, 5), vec![0x51, 0x03]);
    let txid = tx.txid();
    let (_dir, mut writer) = writer()?;

    writer.commit_block(0, &consensus_bytes(&block(vec![tx])))?;

    let rows = writer.indexer().iter_txid_rows(&txid)?;
    assert!(rows.contains(&TxidRow::row(&txid, 0)));
    Ok(())
}

#[test]
fn resolve_script_history_returns_entries_for_funded_scripthash()
-> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let Some(tx) = block.txs.first() else {
        return Err(std::io::Error::other("genesis block has no transactions").into());
    };
    let Some(output) = tx.outputs.first() else {
        return Err(std::io::Error::other("genesis transaction has no outputs").into());
    };
    let scripthash = ScriptHash::from_script_bytes(&output.script_pubkey);
    let txid = tx.txid();
    let (_dir, mut writer) = writer()?;

    writer.commit_block(0, &consensus_bytes(&block))?;

    let source = FakeSource {
        block,
        target_height: 0,
    };
    let entries = writer
        .indexer()
        .resolve_script_history(scripthash, &source)?;

    assert_eq!(entries, vec![ScriptHistoryEntry::confirmed(txid, 0)]);
    Ok(())
}
#[test]
fn resolve_unspent_outputs_returns_txid_vout_value_for_funded_scripthash()
-> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let Some(tx) = block.txs.first() else {
        return Err(std::io::Error::other("genesis block has no transactions").into());
    };
    let Some(output) = tx.outputs.first() else {
        return Err(std::io::Error::other("genesis transaction has no outputs").into());
    };
    let scripthash = ScriptHash::from_script_bytes(&output.script_pubkey);
    let txid = tx.txid();
    let value = output.value.to_sat();
    let (_dir, mut writer) = writer()?;

    writer.commit_block(0, &consensus_bytes(&block))?;

    let source = FakeSource {
        block,
        target_height: 0,
    };
    let outputs = writer
        .indexer()
        .resolve_unspent_outputs(scripthash, &source)?;

    assert_eq!(outputs, vec![(txid, 0, value)]);
    Ok(())
}

#[test]
fn resolve_transaction_returns_coinbase_for_genesis_block_indexed_at_height_zero()
-> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let Some(tx) = block.txs.first() else {
        return Err(std::io::Error::other("genesis block has no transactions").into());
    };
    let coinbase = tx.clone();
    let txid = tx.txid();
    let (_dir, mut writer) = writer()?;

    writer.commit_block(0, &consensus_bytes(&block))?;

    let source = FakeSource {
        block,
        target_height: 0,
    };
    let resolved = writer.indexer().resolve_transaction(txid, &source)?;

    assert_eq!(resolved, Some(coinbase));
    Ok(())
}

#[test]
fn resolve_transaction_returns_none_when_indexed_height_is_not_visible()
-> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let Some(tx) = block.txs.first() else {
        return Err(std::io::Error::other("genesis block has no transactions").into());
    };
    let txid = tx.txid();
    let (_dir, mut writer) = writer()?;

    writer.commit_block(0, &consensus_bytes(&block))?;

    let source = FakeSource {
        block,
        target_height: 1,
    };
    let resolved = writer.indexer().resolve_transaction(txid, &source)?;

    assert_eq!(resolved, None);
    Ok(())
}

#[test]
fn resolve_tx_with_height_returns_genesis_coinbase_at_height_zero()
-> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let Some(tx) = block.txs.first() else {
        return Err(std::io::Error::other("genesis block has no transactions").into());
    };
    let coinbase = tx.clone();
    let txid = tx.txid();
    let (_dir, mut writer) = writer()?;

    writer.commit_block(0, &consensus_bytes(&block))?;

    let source = FakeSource {
        block,
        target_height: 0,
    };
    let resolved = writer.indexer().resolve_tx_with_height(txid, &source)?;

    assert_eq!(resolved, Some((coinbase, 0)));
    Ok(())
}

#[test]
fn resolve_tx_with_height_returns_none_for_unknown_txid() -> Result<(), Box<dyn std::error::Error>>
{
    let (_dir, writer) = writer()?;
    let txid = Txid(Hash256::from_le_bytes(&[0xff; 32]));
    let source = FakeSource {
        block: Network::Regtest.genesis_block(),
        target_height: 0,
    };

    assert_eq!(
        writer.indexer().resolve_tx_with_height(txid, &source)?,
        None
    );
    Ok(())
}

#[test]
fn resolve_outpoint_value_returns_genesis_coinbase_subsidy()
-> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let Some(tx) = block.txs.first() else {
        return Err(std::io::Error::other("genesis block has no transactions").into());
    };
    let txid = tx.txid();
    let (_dir, mut writer) = writer()?;

    writer.commit_block(0, &consensus_bytes(&block))?;

    let source = FakeSource {
        block,
        target_height: 0,
    };
    let outpoint = OutPoint { txid, vout: 0 };
    let value = writer.indexer().resolve_outpoint_value(outpoint, &source)?;

    assert_eq!(value, Some(5_000_000_000));
    Ok(())
}

#[test]
fn resolve_outpoint_value_via_dyn_block_source() -> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let Some(tx) = block.txs.first() else {
        return Err(std::io::Error::other("genesis block has no transactions").into());
    };
    let txid = tx.txid();
    let (_dir, mut writer) = writer()?;

    writer.commit_block(0, &consensus_bytes(&block))?;

    let source = FakeSource {
        block,
        target_height: 0,
    };
    let dyn_source: &dyn super::BlockSource = &source;
    let outpoint = OutPoint { txid, vout: 0 };
    let value = writer
        .indexer()
        .resolve_outpoint_value(outpoint, dyn_source)?;

    assert_eq!(value, Some(5_000_000_000));
    Ok(())
}

#[test]
fn resolve_outpoint_value_returns_none_for_vout_out_of_range()
-> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let Some(tx) = block.txs.first() else {
        return Err(std::io::Error::other("genesis block has no transactions").into());
    };
    let txid = tx.txid();
    let (_dir, mut writer) = writer()?;

    writer.commit_block(0, &consensus_bytes(&block))?;

    let source = FakeSource {
        block,
        target_height: 0,
    };
    let outpoint = OutPoint { txid, vout: 99 };

    assert_eq!(
        writer.indexer().resolve_outpoint_value(outpoint, &source)?,
        None
    );
    Ok(())
}

#[test]
fn resolve_outpoint_value_returns_none_for_unknown_txid() -> Result<(), Box<dyn std::error::Error>>
{
    let (_dir, writer) = writer()?;
    let outpoint = OutPoint {
        txid: Txid(Hash256::from_le_bytes(&[0xff; 32])),
        vout: 0,
    };
    let source = FakeSource {
        block: Network::Regtest.genesis_block(),
        target_height: 0,
    };

    assert_eq!(
        writer.indexer().resolve_outpoint_value(outpoint, &source)?,
        None
    );
    Ok(())
}

#[test]
fn resolve_unspent_outputs_with_height_returns_funding_height()
-> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let Some(tx) = block.txs.first() else {
        return Err(std::io::Error::other("genesis block has no transactions").into());
    };
    let Some(output) = tx.outputs.first() else {
        return Err(std::io::Error::other("genesis transaction has no outputs").into());
    };
    let scripthash = ScriptHash::from_script_bytes(&output.script_pubkey);
    let txid = tx.txid();
    let value = output.value.to_sat();
    let (_dir, mut writer) = writer()?;

    writer.commit_block(0, &consensus_bytes(&block))?;

    let source = FakeSource {
        block,
        target_height: 0,
    };
    let outputs = writer
        .indexer()
        .resolve_unspent_outputs_with_height(scripthash, &source)?;

    assert_eq!(outputs, vec![(txid, 0, value, 0)]);
    Ok(())
}

struct FakeSource {
    block: Block,
    target_height: u32,
}

impl BlockSource for FakeSource {
    fn block_at_height(&self, height: u32) -> Option<Block> {
        if height == self.target_height {
            return Some(self.block.clone());
        }
        None
    }
}

/// A block whose rows populate all four column families: a coinbase plus a
/// spend, so funding and spending rows both exist alongside txid and header
/// rows.
fn rollback_fixture_block() -> Block {
    let funded = tx(OutPoint::new(Txid::default(), u32::MAX), vec![0x51]);
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

    writer.commit_rollback_one(None, &body)?;
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
        writer.commit_rollback_one(None, &body),
        Err(IndexError::NonContiguousPrepared { watermark: None })
    ));
    assert!(stored_rows(writer.indexer())?.is_empty());
    Ok(())
}

#[test]
fn a_second_rollback_is_rejected_once_the_watermark_is_gone()
-> Result<(), Box<dyn std::error::Error>> {
    let (_dir, mut writer) = writer()?;
    let candidate = rollback_fixture_block();
    let body = consensus_bytes(&candidate);
    writer.commit_block(0, &body)?;
    writer.commit_rollback_one(None, &body)?;
    let after_first = stored_rows(writer.indexer())?;

    assert!(matches!(
        writer.commit_rollback_one(None, &body),
        Err(IndexError::NonContiguousPrepared { watermark: None })
    ));
    assert_eq!(
        stored_rows(writer.indexer())?,
        after_first,
        "a rejected second rollback must be observationally inert"
    );
    Ok(())
}

/// Delegates reads to a real store but fails every write API, so the
/// all-or-nothing claim on `commit_rollback_one` is exercised through its
/// current conditional durable path.
struct FailingWriteStore(RocksDbStore);

impl bitcoin_rs_storage::KvStore for FailingWriteStore {
    type WriteBatch = <RocksDbStore as KvStore>::WriteBatch;

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

    fn new_batch(&self) -> Self::WriteBatch {
        self.0.new_batch()
    }

    fn write(&self, _batch: Self::WriteBatch) -> Result<(), bitcoin_rs_storage::StorageError> {
        Err(bitcoin_rs_storage::StorageError::Backend(
            "injected write failure".to_owned(),
        ))
    }

    fn write_durable_if(
        &self,
        _conditions: &[bitcoin_rs_storage::WriteCondition<'_>],
        _batch: Self::WriteBatch,
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
    let outcome = writer.commit_rollback_one(None, &body);
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

/// A rollback of a replaced tip must not delete the replacement's rows.
///
/// `commit_rollback_one` checks the current watermark hash against the
/// serialized body, so a stale body's identity cannot satisfy the tip
/// and the replacement's prefix-colliding history stays put.
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
    writer.commit_rollback_one(None, &old_body)?;
    writer.commit_block(0, &consensus_bytes(&replacement))?;
    writer.flush()?;
    let after_replacement = stored_rows(writer.indexer())?;
    assert!(
        !after_replacement.is_empty(),
        "the replacement must have written rows"
    );

    assert!(
        writer.commit_rollback_one(None, &old_body).is_err(),
        "rolling back the old body against the replacement watermark must fail"
    );
    writer.flush()?;

    assert_eq!(
        stored_rows(writer.indexer())?,
        after_replacement,
        "a stale rollback body must not touch the replacement's rows"
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
        for row in indexer.store().iter_prefix(cf, &[])? {
            let (key, _value) = row?;
            rows.push((cf, key));
        }
    }
    rows.sort_by(|left, right| {
        (left.0.as_str(), left.1.as_slice()).cmp(&(right.0.as_str(), right.1.as_slice()))
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
