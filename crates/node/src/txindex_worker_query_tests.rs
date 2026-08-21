use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use arc_swap::ArcSwapOption;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime, transaction::Version,
};
use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_index::{ScriptHashRow, SpendingPrefixRow, TxidRow};
use bitcoin_rs_rpc::BlockRecord;
use bitcoin_rs_storage::{ColumnFamily, PrefixScan, PrefixScanLimit};

use super::*;

#[derive(Clone)]
struct ScanResponse {
    cf: ColumnFamily,
    prefix: Vec<u8>,
    scan: PrefixScan,
}

#[derive(Clone)]
struct QuerySnapshot {
    watermark: IndexWatermark,
    scans: Vec<ScanResponse>,
    aba: Option<Arc<AbaMutation>>,
}

impl QuerySnapshot {
    fn scan_for(&self, cf: ColumnFamily, prefix: &[u8]) -> PrefixScan {
        self.scans
            .iter()
            .find(|response| response.cf == cf && response.prefix == prefix)
            .map_or(
                PrefixScan {
                    rows: Vec::new(),
                    complete: true,
                },
                |response| response.scan.clone(),
            )
    }

    fn typed_scan(&self, cf: ColumnFamily, prefix: &[u8]) -> Result<TxIndexScan, IndexError> {
        if let Some(aba) = &self.aba {
            aba.trigger_on(cf, prefix);
        }
        let scan = self.scan_for(cf, prefix);
        let encoded_bytes = scan.rows.iter().fold(0_usize, |total, (key, value)| {
            total.saturating_add(key.len()).saturating_add(value.len())
        });
        let mut rows = Vec::with_capacity(scan.rows.len());
        for (key, value) in scan.rows {
            if key.len() != bitcoin_rs_index::HASH_PREFIX_ROW_SIZE {
                return Err(IndexError::InvalidPrefixRowLength { len: key.len() });
            }
            let prefix = key[..bitcoin_rs_index::HASH_PREFIX_LEN]
                .try_into()
                .map_err(|_| IndexError::InvalidPrefixRowLength { len: key.len() })?;
            let height = key
                [bitcoin_rs_index::HASH_PREFIX_LEN..bitcoin_rs_index::HASH_PREFIX_ROW_SIZE]
                .try_into()
                .map_err(|_| IndexError::InvalidPrefixRowLength { len: key.len() })?;
            rows.push(TxIndexScanRow {
                row: HashPrefixRow { prefix, height },
                value,
            });
        }
        Ok(TxIndexScan {
            rows,
            encoded_bytes,
            complete: scan.complete,
        })
    }
}

impl TxIndexSnapshot for QuerySnapshot {
    fn watermark(&self) -> Result<Option<IndexWatermark>, IndexError> {
        Ok(Some(self.watermark))
    }

    fn transaction_rows(
        &self,
        txid: &Txid,
        _limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        self.typed_scan(ColumnFamily::TxConfirmed, &TxidRow::scan_prefix(txid))
    }

    fn funding_rows(
        &self,
        scripthash: ScriptHash,
        _limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        self.typed_scan(
            ColumnFamily::Funding,
            &ScriptHashRow::scan_prefix(scripthash),
        )
    }

    fn spending_rows(
        &self,
        outpoint: &OutPoint,
        _limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        self.typed_scan(
            ColumnFamily::Spending,
            &SpendingPrefixRow::scan_prefix(outpoint),
        )
    }
}

struct QueryReader {
    snapshot: QuerySnapshot,
}

impl IndexReader for QueryReader {
    fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError> {
        Ok(Box::new(self.snapshot.clone()))
    }
}

struct AbaMutation {
    trigger_cf: ColumnFamily,
    trigger_prefix: Vec<u8>,
    triggered: AtomicBool,
    runtime: Arc<TxIndexRuntime>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    away: Arc<TipSnapshot>,
    home: Arc<TipSnapshot>,
}

impl AbaMutation {
    fn trigger_on(&self, cf: ColumnFamily, prefix: &[u8]) {
        if cf != self.trigger_cf
            || prefix != self.trigger_prefix
            || self.triggered.swap(true, Ordering::AcqRel)
        {
            return;
        }

        self.applied_tip.store(Some(Arc::clone(&self.away)));
        self.runtime.wake();
        self.applied_tip.store(Some(Arc::clone(&self.home)));
        self.runtime.wake();
    }
}

struct FixtureConfig {
    block: Block,
    retain_body: bool,
    scans: Vec<ScanResponse>,
    aba_trigger: Option<(ColumnFamily, Vec<u8>)>,
    watermark: Option<IndexWatermark>,
}

struct QueryFixture {
    engine: TxIndexQueryEngine,
}

struct CountingBodySource {
    full_calls: Arc<AtomicUsize>,
    range_calls: Arc<AtomicUsize>,
    bytes: Vec<u8>,
}

impl BlockBodySource for CountingBodySource {
    fn block_body(&self, _height: u32, _hash: Hash256) -> Option<Vec<u8>> {
        self.full_calls.fetch_add(1, Ordering::AcqRel);
        Some(self.bytes.clone())
    }

    fn block_body_range(
        &self,
        _height: u32,
        _hash: Hash256,
        offset: u32,
        len: u32,
    ) -> Option<Vec<u8>> {
        self.range_calls.fetch_add(1, Ordering::AcqRel);
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        Some(self.bytes.get(start..end)?.to_vec())
    }
}

impl QueryFixture {
    fn new(config: FixtureConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let tip_id = tree.insert_header(config.block.header, NodeStatus::HeaderValid)?;
        let node = tree.node(tip_id)?;
        let tip = TipSnapshot {
            tip_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        };
        let tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let home = Arc::new(tip.clone());
        applied_tip.store(Some(Arc::clone(&home)));

        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = Arc::new(TxIndexRuntime::new(wake_tx));
        let aba = config.aba_trigger.map(|(trigger_cf, trigger_prefix)| {
            let mut away = tip.clone();
            away.hash = Hash256::from_le_bytes(&[0x5a; 32]);
            Arc::new(AbaMutation {
                trigger_cf,
                trigger_prefix,
                triggered: AtomicBool::new(false),
                runtime: Arc::clone(&runtime),
                applied_tip: Arc::clone(&applied_tip),
                away: Arc::new(away),
                home,
            })
        });

        let watermark = config.watermark.unwrap_or(IndexWatermark {
            height: tip.height,
            hash: *tip.hash.as_byte_array(),
        });
        let reader = Arc::new(QueryReader {
            snapshot: QuerySnapshot {
                watermark,
                scans: config.scans,
                aba,
            },
        });
        let records = if config.retain_body {
            vec![BlockRecord::from_block(tip.height, &config.block)]
        } else {
            Vec::new()
        };
        let block_source = NodeBlockSource::new(Arc::new(RwLock::new(
            records.into_iter().collect::<bitcoin_rs_rpc::BlockLog>(),
        )));
        let engine =
            TxIndexQueryEngine::new(runtime, reader, block_source, tree, applied_tip, None);
        Ok(Self { engine })
    }
}

fn scan_response(
    cf: ColumnFamily,
    prefix: impl Into<Vec<u8>>,
    rows: Vec<(Vec<u8>, Vec<u8>)>,
    complete: bool,
) -> ScanResponse {
    ScanResponse {
        cf,
        prefix: prefix.into(),
        scan: PrefixScan { rows, complete },
    }
}

fn transaction_position(
    block: &Block,
    transaction_index: usize,
) -> Result<TxPosition, Box<dyn std::error::Error>> {
    let transaction = block
        .txdata
        .get(transaction_index)
        .ok_or_else(|| std::io::Error::other("test transaction index out of bounds"))?;
    let block_bytes = bitcoin::consensus::serialize(block);
    let transaction_bytes = bitcoin::consensus::serialize(transaction);
    let offset = block_bytes
        .windows(transaction_bytes.len())
        .position(|window| window == transaction_bytes)
        .ok_or_else(|| std::io::Error::other("serialized block must contain its transaction"))?;
    Ok(TxPosition::new(
        u32::try_from(offset)?,
        u32::try_from(transaction_bytes.len())?,
    ))
}

#[test]
fn exhausted_block_budget_rejects_before_body_io() -> Result<(), Box<dyn std::error::Error>> {
    let block = genesis_block(Network::Regtest);
    let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
    let full_calls = Arc::new(AtomicUsize::new(0));
    let range_calls = Arc::new(AtomicUsize::new(0));
    let mut fixture = QueryFixture::new(FixtureConfig {
        block: block.clone(),
        retain_body: false,
        scans: Vec::new(),
        aba_trigger: None,
        watermark: None,
    })?;
    fixture.engine.body_source = Some(Arc::new(CountingBodySource {
        full_calls: Arc::clone(&full_calls),
        range_calls: Arc::clone(&range_calls),
        bytes: bitcoin::consensus::serialize(&block),
    }));
    let mut budget = QueryBudget::new();
    budget.remaining_body_reads = 0;

    assert!(matches!(
        fixture.engine.resolve_block(&mut budget, 0, hash),
        Err(TxQueryError::Unavailable(_))
    ));
    assert_eq!(full_calls.load(Ordering::Acquire), 0);
    assert_eq!(range_calls.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn transaction_uses_positioned_range_without_full_body_load()
-> Result<(), Box<dyn std::error::Error>> {
    let block = genesis_block(Network::Regtest);
    let txid = block.txdata[0].compute_txid();
    let value = TxPositionValue::encode(&[transaction_position(&block, 0)?]);
    let full_calls = Arc::new(AtomicUsize::new(0));
    let range_calls = Arc::new(AtomicUsize::new(0));
    let mut fixture = QueryFixture::new(FixtureConfig {
        block: block.clone(),
        retain_body: false,
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            TxidRow::scan_prefix(&txid),
            vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), value)],
            true,
        )],
        aba_trigger: None,
        watermark: None,
    })?;
    fixture.engine.body_source = Some(Arc::new(CountingBodySource {
        full_calls: Arc::clone(&full_calls),
        range_calls: Arc::clone(&range_calls),
        bytes: bitcoin::consensus::serialize(&block),
    }));

    assert_eq!(
        fixture
            .engine
            .transaction(&txid)?
            .map(|tx| tx.compute_txid()),
        Some(txid)
    );
    assert_eq!(range_calls.load(Ordering::Acquire), 1);
    assert_eq!(full_calls.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn duplicate_positions_fall_back_before_range_io() -> Result<(), Box<dyn std::error::Error>> {
    let block = genesis_block(Network::Regtest);
    let txid = block.txdata[0].compute_txid();
    let position = transaction_position(&block, 0)?;
    let value = TxPositionValue::encode(&[position, position]);
    let full_calls = Arc::new(AtomicUsize::new(0));
    let range_calls = Arc::new(AtomicUsize::new(0));
    let mut fixture = QueryFixture::new(FixtureConfig {
        block: block.clone(),
        retain_body: false,
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            TxidRow::scan_prefix(&txid),
            vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), value)],
            true,
        )],
        aba_trigger: None,
        watermark: None,
    })?;
    fixture.engine.body_source = Some(Arc::new(CountingBodySource {
        full_calls: Arc::clone(&full_calls),
        range_calls: Arc::clone(&range_calls),
        bytes: bitcoin::consensus::serialize(&block),
    }));

    assert!(fixture.engine.transaction(&txid)?.is_some());
    assert_eq!(range_calls.load(Ordering::Acquire), 0);
    assert_eq!(full_calls.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn wrong_positioned_transaction_falls_back_to_complete_block()
-> Result<(), Box<dyn std::error::Error>> {
    let mut block = genesis_block(Network::Regtest);
    block.txdata.push(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: Vec::new(),
    });
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or_else(|| std::io::Error::other("test block must have a merkle root"))?;
    let txid = block.txdata[0].compute_txid();
    let value = TxPositionValue::encode(&[transaction_position(&block, 1)?]);
    let full_calls = Arc::new(AtomicUsize::new(0));
    let range_calls = Arc::new(AtomicUsize::new(0));
    let mut fixture = QueryFixture::new(FixtureConfig {
        block: block.clone(),
        retain_body: false,
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            TxidRow::scan_prefix(&txid),
            vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), value)],
            true,
        )],
        aba_trigger: None,
        watermark: None,
    })?;
    fixture.engine.body_source = Some(Arc::new(CountingBodySource {
        full_calls: Arc::clone(&full_calls),
        range_calls: Arc::clone(&range_calls),
        bytes: bitcoin::consensus::serialize(&block),
    }));

    assert_eq!(
        fixture
            .engine
            .transaction(&txid)?
            .map(|tx| tx.compute_txid()),
        Some(txid)
    );
    assert_eq!(range_calls.load(Ordering::Acquire), 1);
    assert_eq!(full_calls.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn funding_history_uses_positioned_range_without_full_body_load()
-> Result<(), Box<dyn std::error::Error>> {
    let block = genesis_block(Network::Regtest);
    let txid = block.txdata[0].compute_txid();
    let scripthash = ScriptHash::new(&block.txdata[0].output[0].script_pubkey);
    let value = TxPositionValue::encode(&[transaction_position(&block, 0)?]);
    let full_calls = Arc::new(AtomicUsize::new(0));
    let range_calls = Arc::new(AtomicUsize::new(0));
    let mut fixture = QueryFixture::new(FixtureConfig {
        block: block.clone(),
        retain_body: false,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            vec![(
                ScriptHashRow::row(scripthash, 0).to_db_row().to_vec(),
                value,
            )],
            true,
        )],
        aba_trigger: None,
        watermark: None,
    })?;
    fixture.engine.body_source = Some(Arc::new(CountingBodySource {
        full_calls: Arc::clone(&full_calls),
        range_calls: Arc::clone(&range_calls),
        bytes: bitcoin::consensus::serialize(&block),
    }));

    let snapshot = fixture.engine.confirmed_history_snapshot(scripthash)?;
    assert_eq!(snapshot.history.len(), 1);
    assert_eq!(snapshot.history[0].txid, txid);
    assert_eq!(snapshot.unspent, snapshot.history);
    assert_eq!(range_calls.load(Ordering::Acquire), 1);
    assert_eq!(full_calls.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn wrong_positioned_funding_falls_back_to_complete_block() -> Result<(), Box<dyn std::error::Error>>
{
    let mut block = genesis_block(Network::Regtest);
    block.txdata.push(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: Vec::new(),
    });
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or_else(|| std::io::Error::other("test block must have a merkle root"))?;
    let txid = block.txdata[0].compute_txid();
    let scripthash = ScriptHash::new(&block.txdata[0].output[0].script_pubkey);
    let value = TxPositionValue::encode(&[transaction_position(&block, 1)?]);
    let full_calls = Arc::new(AtomicUsize::new(0));
    let range_calls = Arc::new(AtomicUsize::new(0));
    let mut fixture = QueryFixture::new(FixtureConfig {
        block: block.clone(),
        retain_body: false,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            vec![(
                ScriptHashRow::row(scripthash, 0).to_db_row().to_vec(),
                value,
            )],
            true,
        )],
        aba_trigger: None,
        watermark: None,
    })?;
    fixture.engine.body_source = Some(Arc::new(CountingBodySource {
        full_calls: Arc::clone(&full_calls),
        range_calls: Arc::clone(&range_calls),
        bytes: bitcoin::consensus::serialize(&block),
    }));

    let snapshot = fixture.engine.confirmed_history_snapshot(scripthash)?;
    assert_eq!(snapshot.history.len(), 1);
    assert_eq!(snapshot.history[0].txid, txid);
    assert_eq!(snapshot.unspent, snapshot.history);
    assert_eq!(range_calls.load(Ordering::Acquire), 1);
    assert_eq!(full_calls.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn transaction_retries_after_applied_tip_aba_revision_change()
-> Result<(), Box<dyn std::error::Error>> {
    let block = genesis_block(Network::Regtest);
    let txid = block.txdata[0].compute_txid();
    let prefix = TxidRow::scan_prefix(&txid).to_vec();
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: false,
        scans: Vec::new(),
        aba_trigger: Some((ColumnFamily::TxConfirmed, prefix)),
        watermark: None,
    })?;

    assert!(matches!(
        fixture.engine.transaction(&txid),
        Err(TxQueryError::Retry)
    ));
    Ok(())
}

#[test]
fn transaction_rejects_watermark_from_rival_tip() -> Result<(), Box<dyn std::error::Error>> {
    let block = genesis_block(Network::Regtest);
    let txid = block.txdata[0].compute_txid();
    let prefix = TxidRow::scan_prefix(&txid);
    let indexed_row = TxidRow::row(&txid, 0).to_db_row().to_vec();
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            prefix,
            vec![(indexed_row, Vec::new())],
            true,
        )],
        aba_trigger: None,
        watermark: Some(IndexWatermark {
            height: 0,
            hash: [0x5a; 32],
        }),
    })?;

    assert!(matches!(
        fixture.engine.transaction(&txid),
        Err(TxQueryError::Retry)
    ));
    Ok(())
}

#[test]
fn transaction_rejects_incomplete_prefix_scan() -> Result<(), Box<dyn std::error::Error>> {
    let block = genesis_block(Network::Regtest);
    let txid = block.txdata[0].compute_txid();
    let prefix = TxidRow::scan_prefix(&txid);
    let tempting_row = TxidRow::row(&txid, 0).to_db_row().to_vec();
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            prefix,
            vec![(tempting_row, Vec::new())],
            false,
        )],
        aba_trigger: None,
        watermark: None,
    })?;

    assert!(matches!(
        fixture.engine.transaction(&txid),
        Err(TxQueryError::Unavailable(_))
    ));
    Ok(())
}

#[test]
fn transaction_reports_unavailable_when_indexed_body_is_missing()
-> Result<(), Box<dyn std::error::Error>> {
    let block = genesis_block(Network::Regtest);
    let txid = block.txdata[0].compute_txid();
    let prefix = TxidRow::scan_prefix(&txid);
    let indexed_row = TxidRow::row(&txid, 0).to_db_row().to_vec();
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: false,
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            prefix,
            vec![(indexed_row, Vec::new())],
            true,
        )],
        aba_trigger: None,
        watermark: None,
    })?;

    assert!(matches!(
        fixture.engine.transaction(&txid),
        Err(TxQueryError::Unavailable(_))
    ));
    Ok(())
}

#[test]
fn unspent_outputs_preserve_distinct_vouts_for_same_transaction_and_script()
-> Result<(), Box<dyn std::error::Error>> {
    let mut block = genesis_block(Network::Regtest);
    let transaction = &mut block.txdata[0];
    transaction.output.push(transaction.output[0].clone());
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or_else(|| std::io::Error::other("test block must have a merkle root"))?;

    let txid: Txid = block.txdata[0].compute_txid();
    let script = block.txdata[0].output[0].script_pubkey.clone();
    let scripthash = ScriptHash::new(&script);
    let funding_row = ScriptHashRow::row(scripthash, 0).to_db_row().to_vec();
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            vec![(funding_row, Vec::new())],
            true,
        )],
        aba_trigger: None,
        watermark: None,
    })?;

    let outputs = fixture.engine.unspent_outputs(scripthash)?;
    let identities: Vec<_> = outputs
        .iter()
        .map(|output| (output.txid, output.vout))
        .collect();
    assert_eq!(identities, vec![(txid, 0), (txid, 1)]);
    Ok(())
}

#[test]
fn unspent_outputs_reject_aggregate_scan_budget_exhaustion()
-> Result<(), Box<dyn std::error::Error>> {
    let mut block = genesis_block(Network::Regtest);
    let transaction = &mut block.txdata[0];
    let output = transaction.output[0].clone();
    transaction
        .output
        .extend(std::iter::repeat_n(output, QUERY_SCAN_COUNT_LIMIT - 1));
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or_else(|| std::io::Error::other("test block must have a merkle root"))?;

    let scripthash = ScriptHash::new(&block.txdata[0].output[0].script_pubkey);
    let funding_row = ScriptHashRow::row(scripthash, 0).to_db_row().to_vec();
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            vec![(funding_row, Vec::new())],
            true,
        )],
        aba_trigger: None,
        watermark: None,
    })?;

    assert!(matches!(
        fixture.engine.unspent_outputs(scripthash),
        Err(ElectrumError::Unavailable(_))
    ));
    Ok(())
}

#[test]
fn confirmed_history_snapshot_matches_history_and_unspent_for_funding()
-> Result<(), Box<dyn std::error::Error>> {
    let block = genesis_block(Network::Regtest);
    let txid = block.txdata[0].compute_txid();
    let script = block.txdata[0].output[0].script_pubkey.clone();
    let value = block.txdata[0].output[0].value.to_sat();
    let scripthash = ScriptHash::new(&script);
    let funding_row = ScriptHashRow::row(scripthash, 0).to_db_row().to_vec();
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            vec![(funding_row, Vec::new())],
            true,
        )],
        aba_trigger: None,
        watermark: None,
    })?;

    let snapshot = fixture.engine.confirmed_history_snapshot(scripthash)?;
    assert_eq!(snapshot.history.len(), 1);
    assert_eq!(snapshot.unspent.len(), 1);

    let expected = bitcoin_rs_electrum::methods::HistoryRecord {
        txid,
        height: 0,
        value,
        vout: 0,
        spent: false,
    };
    assert_eq!(snapshot.history[0], expected);
    assert_eq!(snapshot.unspent[0], expected);
    Ok(())
}

#[test]
fn confirmed_history_snapshot_omits_spent_output_from_unspent()
-> Result<(), Box<dyn std::error::Error>> {
    let mut block = genesis_block(Network::Regtest);
    let coinbase = &mut block.txdata[0];
    let txid = coinbase.compute_txid();
    let script = coinbase.output[0].script_pubkey.clone();
    let scripthash = ScriptHash::new(&script);
    let value = coinbase.output[0].value.to_sat();

    let spend_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    block.txdata.push(spend_tx);
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or_else(|| std::io::Error::other("test block must have a merkle root"))?;

    let funding_row = ScriptHashRow::row(scripthash, 0).to_db_row().to_vec();
    let spend_txid = block.txdata[1].compute_txid();
    let spend_prefix = SpendingPrefixRow::scan_prefix(&OutPoint { txid, vout: 0 }).to_vec();
    let spending_row = SpendingPrefixRow::row(&OutPoint { txid, vout: 0 }, 0)
        .to_db_row()
        .to_vec();
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        scans: vec![
            scan_response(
                ColumnFamily::Funding,
                ScriptHashRow::scan_prefix(scripthash),
                vec![(funding_row, Vec::new())],
                true,
            ),
            scan_response(
                ColumnFamily::Spending,
                spend_prefix,
                vec![(spending_row, Vec::new())],
                true,
            ),
        ],
        aba_trigger: None,
        watermark: None,
    })?;

    let snapshot = fixture.engine.confirmed_history_snapshot(scripthash)?;
    assert!(snapshot.unspent.is_empty());
    assert_eq!(snapshot.history.len(), 2);

    let funding_record = bitcoin_rs_electrum::methods::HistoryRecord {
        txid,
        height: 0,
        value,
        vout: 0,
        spent: false,
    };
    let spending_record = bitcoin_rs_electrum::methods::HistoryRecord {
        txid: spend_txid,
        height: 0,
        value: 0,
        vout: 0,
        spent: true,
    };
    assert!(snapshot.history.contains(&funding_record));
    assert!(snapshot.history.contains(&spending_record));
    Ok(())
}

#[test]
fn confirmed_history_snapshot_retries_after_aba_on_spending_scan()
-> Result<(), Box<dyn std::error::Error>> {
    let mut block = genesis_block(Network::Regtest);
    let coinbase = &mut block.txdata[0];
    let txid = coinbase.compute_txid();
    let script = coinbase.output[0].script_pubkey.clone();
    let scripthash = ScriptHash::new(&script);
    let value = coinbase.output[0].value.to_sat();

    let spend_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    block.txdata.push(spend_tx);
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or_else(|| std::io::Error::other("test block must have a merkle root"))?;

    let funding_row = ScriptHashRow::row(scripthash, 0).to_db_row().to_vec();
    let spend_prefix = SpendingPrefixRow::scan_prefix(&OutPoint { txid, vout: 0 }).to_vec();
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            vec![(funding_row, Vec::new())],
            true,
        )],
        aba_trigger: Some((ColumnFamily::Spending, spend_prefix)),
        watermark: None,
    })?;

    assert!(matches!(
        fixture.engine.confirmed_history_snapshot(scripthash),
        Err(ElectrumError::Unavailable(_))
    ));
    Ok(())
}

#[test]
fn quiet_wait_uses_authoritative_coalesced_revision() {
    let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
    let runtime = TxIndexRuntime::new(wake_tx);
    runtime.wake();
    runtime.wake();
    runtime.wake();

    assert_eq!(runtime.revision(), 3);
    assert_eq!(
        wait_for_revision_quiet(&runtime, &wake_rx, std::time::Duration::ZERO, 0),
        Some(3)
    );

    runtime.request_shutdown();
    assert_eq!(
        wait_for_revision_quiet(&runtime, &wake_rx, std::time::Duration::ZERO, 3),
        None
    );
}

#[test]
fn batch_deadline_preserves_queued_wakes_for_reconciliation() {
    let (wake_tx, wake_rx) = crossbeam_channel::bounded(4);
    let runtime = TxIndexRuntime::new(wake_tx);
    runtime.wake();
    runtime.wake();
    let deadline = Instant::now() + std::time::Duration::from_secs(1);

    assert_eq!(
        wait_for_batch_deadline(&runtime, &wake_rx, deadline),
        BatchWait::Woken
    );
    assert_eq!(
        wait_for_batch_deadline(&runtime, &wake_rx, deadline),
        BatchWait::Woken
    );
    assert!(wake_rx.is_empty());
    assert_eq!(
        wait_for_batch_deadline(&runtime, &wake_rx, Instant::now()),
        BatchWait::Deadline
    );
}
