use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_index::{ScriptHashRow, SpendingPrefixRow, TxidRow};
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Network, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
    encode::double_sha256,
};
use bitcoin_rs_rpc::context::{BlockRecord, ScriptHistoryRecord};
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
    script_history_watermark: ScriptHistoryWatermark,
    scans: Vec<ScanResponse>,
    aba: Option<Arc<AbaMutation>>,
}

#[derive(Clone, Copy)]
enum ScriptHistoryWatermark {
    MatchTx,
    Override(Option<IndexWatermark>),
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

    fn capability_watermark(
        &self,
        capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        Ok(match capability {
            IndexCapability::TxLookup => Some(self.watermark),
            IndexCapability::ScriptHistory => match self.script_history_watermark {
                ScriptHistoryWatermark::MatchTx => Some(self.watermark),
                ScriptHistoryWatermark::Override(watermark) => watermark,
            },
        })
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

struct SingleBlockBody {
    height: u32,
    hash: BlockHash,
    body: Vec<u8>,
}

impl BlockBodySource for SingleBlockBody {
    fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
        (height == self.height && hash == self.hash).then(|| self.body.clone())
    }
}

impl QueryFixture {
    fn new(config: FixtureConfig) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_script_history_watermark(config, ScriptHistoryWatermark::MatchTx)
    }

    fn new_with_script_history_watermark(
        config: FixtureConfig,
        script_history_watermark: ScriptHistoryWatermark,
    ) -> Result<Self, Box<dyn std::error::Error>> {
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
                script_history_watermark,
                scans: config.scans,
                aba,
            },
        });
        let records = if config.retain_body {
            vec![BlockRecord::from_block(tip.height, &config.block)]
        } else {
            Vec::new()
        };
        let body_source = config.retain_body.then(|| {
            let source: Arc<dyn BlockBodySource> = Arc::new(SingleBlockBody {
                height: tip.height,
                hash: config.block.block_hash(),
                body: consensus_bytes(&config.block),
            });
            source
        });
        let block_source = NodeBlockSource::new(Arc::new(RwLock::new(
            records
                .into_iter()
                .collect::<bitcoin_rs_rpc::context::BlockLog>(),
        )));
        let engine = TxIndexQueryEngine::new(
            runtime,
            reader,
            block_source,
            tree,
            applied_tip,
            body_source,
        );
        Ok(Self { engine })
    }
}

#[test]
fn tx_queries_can_be_ready_while_script_history_is_backfilling()
-> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
    let fixture = QueryFixture::new_with_script_history_watermark(
        FixtureConfig {
            block,
            retain_body: true,
            scans: Vec::new(),
            aba_trigger: None,
            watermark: None,
        },
        ScriptHistoryWatermark::Override(None),
    )?;

    assert!(TxIndexQuery::transaction(&fixture.engine, &txid)?.is_none());
    assert!(matches!(
        fixture
            .engine
            .history_snapshot(ScriptHash::from_script_bytes(&[])),
        Err(TxQueryError::Retry)
    ));
    Ok(())
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

/// Native BIP141-style txid merkle fold with the odd-leaf duplication rule.
fn compute_merkle_root(block: &Block) -> Option<Hash256> {
    let txs = &block.txs;
    if txs.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pos in 0..level.len().div_ceil(2) {
            let left = level[2 * pos];
            let right = level[(2 * pos + 1).min(level.len() - 1)];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(*double_sha256(&pair).as_byte_array());
        }
        level = next;
    }
    Some(Hash256::from_le_bytes(&level[0]))
}

/// Pins that the height query proves absence rather than guessing the tip.
///
/// Without this, an implementation that answered `Some(tip.height)` for anything
/// would satisfy the test, and `gettxoutproof` would build its proof from the
/// wrong block.
#[test]
fn transaction_height_reports_nothing_for_an_unindexed_txid()
-> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: false,
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            TxidRow::scan_prefix(&txid),
            Vec::new(),
            true,
        )],
        aba_trigger: None,
        watermark: None,
    })?;

    assert_eq!(fixture.engine.transaction_height(&txid)?, None);
    Ok(())
}

#[test]
fn transaction_retries_after_applied_tip_aba_revision_change()
-> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
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
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
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
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
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
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
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
    let mut block = Network::Regtest.genesis_block();
    let transaction = &mut block.txs[0];
    transaction.outputs.push(transaction.outputs[0].clone());
    block.header.merkle_root = compute_merkle_root(&block)
        .ok_or_else(|| std::io::Error::other("test block must have a merkle root"))?;

    let txid: Txid = block.txs[0].txid();
    let script = block.txs[0].outputs[0].script_pubkey.clone();
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
    let mut block = Network::Regtest.genesis_block();
    let transaction = &mut block.txs[0];
    let output = transaction.outputs[0].clone();
    transaction
        .outputs
        .extend(std::iter::repeat_n(output, QUERY_SCAN_COUNT_LIMIT - 1));
    block.header.merkle_root = compute_merkle_root(&block)
        .ok_or_else(|| std::io::Error::other("test block must have a merkle root"))?;

    let scripthash = ScriptHash::new(&block.txs[0].outputs[0].script_pubkey);
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
        Err(TxQueryError::Unavailable(_))
    ));
    Ok(())
}

#[test]
fn confirmed_history_snapshot_includes_funding_transaction()
-> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
    let script = block.txs[0].outputs[0].script_pubkey.clone();
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

    let snapshot = fixture.engine.history_snapshot(scripthash)?;
    assert_eq!(snapshot.history.len(), 1);
    let expected = ScriptHistoryRecord { txid, height: 0 };
    assert_eq!(snapshot.history[0], expected);
    Ok(())
}

#[test]
fn confirmed_history_snapshot_includes_the_spending_transaction()
-> Result<(), Box<dyn std::error::Error>> {
    let mut block = Network::Regtest.genesis_block();
    let coinbase = &mut block.txs[0];
    let txid = coinbase.txid();
    let script = coinbase.outputs[0].script_pubkey.clone();
    let scripthash = ScriptHash::new(&script);
    let value = coinbase.outputs[0].value;

    let spend_tx = Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value,
            script_pubkey: Vec::new(),
        }],
    };
    block.txs.push(spend_tx);
    block.header.merkle_root = compute_merkle_root(&block)
        .ok_or_else(|| std::io::Error::other("test block must have a merkle root"))?;

    let funding_row = ScriptHashRow::row(scripthash, 0).to_db_row().to_vec();
    let spend_txid = block.txs[1].txid();
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

    let spender = fixture
        .engine
        .spender(OutPoint { txid, vout: 0 })?
        .ok_or_else(|| std::io::Error::other("indexed spender missing"))?;
    assert_eq!(spender.txid, spend_txid);
    assert_eq!(spender.height, 0);
    assert_eq!(spender.vin, 0);

    let snapshot = fixture.engine.history_snapshot(scripthash)?;
    assert_eq!(snapshot.history.len(), 2);

    let funding_record = ScriptHistoryRecord { txid, height: 0 };
    let spending_record = ScriptHistoryRecord {
        txid: spend_txid,
        height: 0,
    };
    assert!(snapshot.history.contains(&funding_record));
    assert!(snapshot.history.contains(&spending_record));
    Ok(())
}

#[test]
fn confirmed_history_snapshot_retries_after_aba_on_spending_scan()
-> Result<(), Box<dyn std::error::Error>> {
    let mut block = Network::Regtest.genesis_block();
    let coinbase = &mut block.txs[0];
    let txid = coinbase.txid();
    let script = coinbase.outputs[0].script_pubkey.clone();
    let scripthash = ScriptHash::new(&script);
    let value = coinbase.outputs[0].value;

    let spend_tx = Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value,
            script_pubkey: Vec::new(),
        }],
    };
    block.txs.push(spend_tx);
    block.header.merkle_root = compute_merkle_root(&block)
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
        fixture.engine.history_snapshot(scripthash),
        Err(TxQueryError::Retry)
    ));
    Ok(())
}
