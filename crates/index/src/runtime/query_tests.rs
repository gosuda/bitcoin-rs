use crate::TxIndexSnapshot;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::block_log::BlockRecord;
use crate::types::{TxPosition, TxPositionValue};
use crate::{
    HashPrefixRow, IndexCapabilities, ScriptHashRow, ScriptLiveRow, SpendingPrefixRow, TxidRow,
};
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
    Txid, Witness, consensus_bytes, encode::double_sha256,
};
use bitcoin_rs_storage::{ColumnFamily, PrefixScan, PrefixScanLimit};
use bitcoin_rs_utxo::UtxoSet;

use super::*;
use parking_lot::Mutex;

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
    chain_transition: Arc<Mutex<()>>,
}

#[derive(Clone, Copy)]
enum ScriptHistoryWatermark {
    MatchTx,
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
            if key.len() != crate::HASH_PREFIX_ROW_SIZE {
                return Err(IndexError::InvalidPrefixRowLength { len: key.len() });
            }
            let prefix = key[..crate::HASH_PREFIX_LEN]
                .try_into()
                .map_err(|_| IndexError::InvalidPrefixRowLength { len: key.len() })?;
            let height = key[crate::HASH_PREFIX_LEN..crate::HASH_PREFIX_ROW_SIZE]
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
        _capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        let _ = self.script_history_watermark;
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

    fn live_rows(
        &self,
        scripthash: ScriptHash,
        _limit: PrefixScanLimit,
    ) -> Result<crate::ScriptLiveScan, IndexError> {
        assert!(
            self.chain_transition.try_lock().is_none(),
            "ScriptLive scan must run under chain-transition authority"
        );
        if let Some(aba) = &self.aba {
            aba.trigger_on(
                ColumnFamily::ScriptLive,
                &ScriptHashRow::scan_prefix(scripthash),
            );
        }
        let scan = self.scan_for(
            ColumnFamily::ScriptLive,
            &ScriptHashRow::scan_prefix(scripthash),
        );
        let encoded_bytes = scan.rows.iter().fold(0_usize, |total, (key, value)| {
            total.saturating_add(key.len()).saturating_add(value.len())
        });
        let mut rows = Vec::with_capacity(scan.rows.len());
        for (key, value) in scan.rows {
            if !value.is_empty() {
                return Err(IndexError::InvalidLiveRowValue { len: value.len() });
            }
            rows.push(
                ScriptLiveRow::from_db_row(&key)
                    .ok_or(IndexError::InvalidPrefixRowLength { len: key.len() })?,
            );
        }
        Ok(crate::ScriptLiveScan {
            rows,
            encoded_bytes,
            complete: scan.complete,
        })
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
    runtime: Arc<DerivedIndexRuntime>,
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
    engine: DerivedIndexQueryEngine,
    body: Option<Arc<SingleBlockBody>>,
}

pub(super) struct SingleBlockBody {
    pub(super) height: u32,
    pub(super) hash: BlockHash,
    pub(super) body: Vec<u8>,
    pub(super) full_reads: AtomicUsize,
    pub(super) range_reads: AtomicUsize,
}

impl BlockBodySource for SingleBlockBody {
    fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
        if height == self.height && hash == self.hash {
            self.full_reads.fetch_add(1, Ordering::Relaxed);
        }
        (height == self.height && hash == self.hash).then(|| self.body.clone())
    }

    fn block_body_range(
        &self,
        height: u32,
        hash: BlockHash,
        offset: u32,
        len: u32,
    ) -> Option<Vec<u8>> {
        if height != self.height || hash != self.hash {
            return None;
        }
        self.range_reads.fetch_add(1, Ordering::Relaxed);
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        self.body.get(start..end).map(<[u8]>::to_vec)
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
        let chain_transition = Arc::new(Mutex::new(()));

        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
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
                script_history_watermark: ScriptHistoryWatermark::MatchTx,
                scans: config.scans,
                aba,
                chain_transition: Arc::clone(&chain_transition),
            },
        });
        let records = if config.retain_body {
            vec![BlockRecord::from_block(tip.height, &config.block)]
        } else {
            Vec::new()
        };
        let body = config.retain_body.then(|| {
            Arc::new(SingleBlockBody {
                height: tip.height,
                hash: config.block.block_hash(),
                body: consensus_bytes(&config.block),
                full_reads: AtomicUsize::new(0),
                range_reads: AtomicUsize::new(0),
            })
        });
        let body_source: Option<Arc<dyn BlockBodySource>> = body.as_ref().map(|source| {
            let source: Arc<dyn BlockBodySource> = source.clone();
            source
        });
        let block_source = IndexBlockSource::new(Arc::new(RwLock::new(
            records.into_iter().collect::<crate::block_log::BlockLog>(),
        )));
        let engine = DerivedIndexQueryEngine::new(
            runtime,
            reader,
            block_source,
            tree,
            applied_tip,
            body_source,
            QueryEngineLive {
                utxo: None::<Arc<UtxoSet>>,
                chain_transition: Some(chain_transition),
                enabled: IndexCapabilities::ALL,
            },
        );
        Ok(Self { engine, body })
    }

    fn full_reads(&self) -> Result<usize, std::io::Error> {
        self.body
            .as_ref()
            .map(|body| body.full_reads.load(Ordering::Relaxed))
            .ok_or_else(|| std::io::Error::other("body source"))
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

fn position_of_transaction(block: &Block, index: usize) -> Result<TxPosition, std::io::Error> {
    let body = consensus_bytes(block);
    let transaction = consensus_bytes(&block.txs[index]);
    let offset = body
        .windows(transaction.len())
        .position(|window| window == transaction)
        .ok_or_else(|| std::io::Error::other("transaction must be present"))?;
    let offset =
        u32::try_from(offset).map_err(|_| std::io::Error::other("transaction offset fits"))?;
    let length = u32::try_from(transaction.len())
        .map_err(|_| std::io::Error::other("transaction length fits"))?;
    Ok(TxPosition::new(offset, length))
}

fn block_with_spending_transaction() -> Result<(Block, OutPoint, ScriptHash, Txid), std::io::Error>
{
    let mut block = Network::Regtest.genesis_block();
    let funding_txid = block.txs[0].txid();
    let script = block.txs[0].outputs[0].script_pubkey.clone();
    let value = block.txs[0].outputs[0].value;
    let outpoint = OutPoint {
        txid: funding_txid,
        vout: 0,
    };
    block.txs.push(Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value,
            script_pubkey: Script::new(),
        }],
    });
    block.header.merkle_root = compute_merkle_root(&block)
        .ok_or_else(|| std::io::Error::other("block has transactions"))?;
    let spend_txid = block.txs[1].txid();
    Ok((block, outpoint, ScriptHash::new(&script), spend_txid))
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
fn spending_position_mismatch_falls_back_to_full_block() -> Result<(), Box<dyn std::error::Error>> {
    let (block, outpoint, _, spend_txid) = block_with_spending_transaction()?;
    let spending_row = SpendingPrefixRow::row(&outpoint, 0).to_db_row().to_vec();
    let fixture = QueryFixture::new(FixtureConfig {
        block: block.clone(),
        retain_body: true,
        scans: vec![scan_response(
            ColumnFamily::Spending,
            SpendingPrefixRow::scan_prefix(&outpoint),
            vec![(
                spending_row,
                TxPositionValue::encode(&[position_of_transaction(&block, 0)?]),
            )],
            true,
        )],
        aba_trigger: None,
        watermark: None,
    })?;

    assert_eq!(
        fixture
            .engine
            .spender(outpoint)?
            .map(|spender| spender.txid),
        Some(spend_txid)
    );
    assert_eq!(fixture.full_reads()?, 1);
    Ok(())
}
