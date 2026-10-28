use crate::TxIndexSnapshot;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::types::{TxPosition, TxPositionValue, TxidRow};
use crate::{HashPrefixRow, IndexCapabilities, ScriptHashRow, ScriptLiveRow, SpendingPrefixRow};
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{NodeStatus, regtest_fixture};
use bitcoin_rs_primitives::{
    Block, BlockHash, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid,
    Witness, consensus_bytes,
};
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
    chain_transition: bitcoin_rs_chain::StableRead,
    funding_scans: Arc<AtomicUsize>,
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
        let scan = self.scan_for(cf, prefix);
        let encoded_bytes = scan.rows.iter().fold(0_usize, |total, (key, value)| {
            total.saturating_add(key.len()).saturating_add(value.len())
        });
        let mut rows = Vec::with_capacity(scan.rows.len());
        for (key, value) in scan.rows {
            if key.len() != crate::HASH_PREFIX_ROW_SIZE {
                return Err(IndexError::InvalidPrefixRowLength { len: key.len() });
            }
            let prefix = key[..crate::types::HASH_PREFIX_LEN]
                .try_into()
                .map_err(|_| IndexError::InvalidPrefixRowLength { len: key.len() })?;
            let height = key[crate::types::HASH_PREFIX_LEN..crate::HASH_PREFIX_ROW_SIZE]
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
    fn capability_watermark(
        &self,
        _capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError> {
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
        self.funding_scans.fetch_add(1, Ordering::Relaxed);
        self.typed_scan(
            ColumnFamily::Funding,
            &ScriptHashRow::scan_prefix(scripthash),
        )
    }

    fn funding_rows_from(
        &self,
        scripthash: ScriptHash,
        start_height: u32,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        let scan = self.funding_rows(scripthash, limit)?;
        let mut candidates = scan.rows;
        candidates.retain(|row| row.row.height() <= start_height);
        candidates.sort_unstable_by_key(|row| core::cmp::Reverse(row.row.height()));
        let mut rows = Vec::new();
        let mut encoded_bytes = 0_usize;
        let mut complete = scan.complete;
        for row in candidates {
            let next_bytes = encoded_bytes
                .saturating_add(12)
                .saturating_add(row.value.len());
            if rows.len() >= limit.max_rows || (!rows.is_empty() && next_bytes > limit.max_bytes) {
                complete = false;
                break;
            }
            encoded_bytes = next_bytes;
            rows.push(row);
        }
        Ok(TxIndexScan {
            rows,
            encoded_bytes,
            complete,
        })
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
            "ScriptLive scan must run under chain-transition exclusion"
        );
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

struct FixtureConfig {
    block: Block,
    retain_body: bool,
    ranged_body: bool,
    scans: Vec<ScanResponse>,
    watermark: Option<IndexWatermark>,
    /// Chained heads built on `block`, in order, for multi-height tests.
    /// Empty for the historical single-block fixtures.
    extra_blocks: Vec<Block>,
    /// Live coins to seed into the authoritative UTXO view, as
    /// `(outpoint, txout, coinbase, height)`. Empty leaves the engine
    /// without a UTXO authority, as before.
    utxo_adds: Vec<(OutPoint, TxOut, bool, u32)>,
}

struct QueryFixture {
    engine: DerivedIndexQueryEngine,
    runtime: Arc<DerivedIndexRuntime>,
    body: Option<Arc<SingleBlockBody>>,
    funding_scans: Arc<AtomicUsize>,
    multi_body: Option<Arc<MultiBlockBody>>,
}

pub(super) struct SingleBlockBody {
    pub(super) height: u32,
    pub(super) hash: BlockHash,
    pub(super) body: Vec<u8>,
    pub(super) ranged: bool,
    pub(super) full_reads: AtomicUsize,
}

impl BlockBodySource for SingleBlockBody {
    fn block_body(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
        if height == self.height && hash == self.hash {
            self.full_reads.fetch_add(1, Ordering::Relaxed);
        }
        Ok((height == self.height && hash == self.hash).then(|| self.body.clone()))
    }

    fn block_body_range(
        &self,
        height: u32,
        hash: BlockHash,
        offset: u32,
        len: u32,
    ) -> Option<Vec<u8>> {
        if !self.ranged || height != self.height || hash != self.hash {
            return None;
        }
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        self.body.get(start..end).map(<[u8]>::to_vec)
    }
}

impl QueryFixture {
    fn new(config: FixtureConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let mut tip_id = tree.insert_header(config.block.header, NodeStatus::HeaderValid)?;
        let mut heights = vec![tree.node(tip_id)?.height];
        let mut blocks = vec![config.block];
        for block in config.extra_blocks {
            tip_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
            heights.push(tree.node(tip_id)?.height);
            blocks.push(block);
        }
        let node = tree.node(tip_id)?;
        let tip = TipSnapshot {
            tip_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: node.chain_tx_count,
        };
        let tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let home = Arc::new(tip.clone());
        applied_tip.store(Some(Arc::clone(&home)));
        let chain_transition = bitcoin_rs_chain::TransitionDomain::new().stable_read();

        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
        let watermark = config.watermark.unwrap_or(IndexWatermark {
            height: tip.height,
            hash: *tip.hash.as_byte_array(),
        });
        let funding_scans = Arc::new(AtomicUsize::new(0));
        let reader = Arc::new(QueryReader {
            snapshot: QuerySnapshot {
                watermark,
                scans: config.scans,
                chain_transition: chain_transition.clone(),
                funding_scans: Arc::clone(&funding_scans),
            },
        });
        let body = if config.retain_body && blocks.len() == 1 {
            Some(Arc::new(SingleBlockBody {
                height: heights[0],
                hash: blocks[0].block_hash(),
                body: consensus_bytes(&blocks[0]),
                ranged: config.ranged_body,
                full_reads: AtomicUsize::new(0),
            }))
        } else {
            None
        };
        let multi_body = if config.retain_body && blocks.len() > 1 {
            Some(Arc::new(MultiBlockBody {
                bodies: heights
                    .iter()
                    .zip(blocks.iter())
                    .map(|(height, block)| (*height, block.block_hash(), consensus_bytes(block)))
                    .collect(),
                full_reads: AtomicUsize::new(0),
            }))
        } else {
            None
        };
        let body_source: Option<Arc<dyn BlockBodySource>> = body
            .as_ref()
            .map(|source| {
                let source: Arc<dyn BlockBodySource> = source.clone();
                source
            })
            .or_else(|| {
                multi_body.as_ref().map(|source| {
                    let source: Arc<dyn BlockBodySource> = source.clone();
                    source
                })
            });
        let engine = DerivedIndexQueryEngine::new(
            Arc::clone(&runtime),
            reader,
            bitcoin_rs_chain::BlockTreeReader::new(tree),
            bitcoin_rs_chain::TipReader::new(applied_tip),
            body_source,
            QueryEngineLive {
                utxo: seed_utxo_reader(config.utxo_adds, tip.hash)?,
                chain_transition: Some(chain_transition),
                enabled: IndexCapabilities::ALL,
            },
        );
        Ok(Self {
            engine,
            runtime,
            body,
            funding_scans,
            multi_body,
        })
    }

    fn full_reads(&self) -> Result<usize, std::io::Error> {
        if self.body.is_none() && self.multi_body.is_none() {
            return Err(std::io::Error::other("body source"));
        }
        let single = self
            .body
            .as_ref()
            .map_or(0, |body| body.full_reads.load(Ordering::Relaxed));
        let multi = self
            .multi_body
            .as_ref()
            .map_or(0, |body| body.full_reads.load(Ordering::Relaxed));
        Ok(single + multi)
    }
}

#[test]
fn unusable_worker_makes_queries_unavailable() -> Result<(), Box<dyn std::error::Error>> {
    for publish in [true, false] {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let fixture = QueryFixture::new(FixtureConfig {
            block,
            retain_body: true,
            ranged_body: true,
            scans: Vec::new(),
            watermark: None,
            extra_blocks: Vec::new(),
            utxo_adds: Vec::new(),
        })?;
        if publish {
            fixture.runtime.publish_failed("injected worker failure");
        } else {
            fixture.runtime.request_shutdown();
        }

        let result = fixture.engine.transaction(&txid);
        if publish {
            assert!(
                matches!(
                    &result,
                    Err(TxQueryError::Unavailable(
                        TxUnavailableCause::WorkerFailed(reason)
                    )) if reason.as_str() == "injected worker failure"
                ),
                "{result:?}"
            );
        } else {
            assert!(
                matches!(
                    &result,
                    Err(TxQueryError::Unavailable(TxUnavailableCause::WorkerStopped))
                ),
                "{result:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn filter_failure_refuses_filters_but_preserves_durable_progress_and_tx_queries()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::CompactFilterQuery;
    let block = Network::Regtest.genesis_block();
    let hash = Hash256::from(block.block_hash());
    let transaction = block.txs[0].clone();
    let txid = transaction.txid();
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        ranged_body: true,
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            TxidRow::scan_prefix(&txid),
            vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), Vec::new())],
            true,
        )],
        watermark: None,
        extra_blocks: Vec::new(),
        utxo_adds: Vec::new(),
    })?;
    fixture
        .runtime
        .fail_compact_filters(&DerivedIndexWorkerError::UndoUnavailable { height: 1, hash });
    assert!(matches!(
        fixture.engine.block_filter(hash),
        Err(TxQueryError::Unavailable(_))
    ));
    assert!(!fixture.engine.filter_index_info()?.synced);
    assert!(fixture.engine.index_info()?.synced);
    assert_eq!(fixture.engine.transaction(&txid)?, Some(transaction));
    assert!(!fixture.runtime.should_stop());
    let lifecycle = Arc::new(ArcSwap::from_pointee(DerivedIndexLifecycle::Serving(
        Arc::new(fixture.engine.clone()),
    )));
    let status = DerivedIndexCapability::new(
        Some(lifecycle.clone()),
        Some(fixture.runtime.clone()),
        IndexCapabilities::ALL,
    );
    for leg in [
        ReconcileLeg::Forward,
        ReconcileLeg::Rebuilding,
        ReconcileLeg::RollingBack {
            from_height: 1,
            to_height: 0,
        },
    ] {
        fixture
            .runtime
            .publish_leg(IndexCapabilities::COMPACT_FILTERS, leg);
        assert_eq!(status.capability().state, CapabilityState::Ready);
    }
    let filters_only = DerivedIndexCapability::new(
        Some(lifecycle),
        Some(fixture.runtime),
        IndexCapabilities::COMPACT_FILTERS,
    )
    .capability();
    assert!(!filters_only.enabled);
    assert_eq!(filters_only.state, CapabilityState::Disabled);
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
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
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
        ranged_body: true,
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            prefix,
            vec![(indexed_row, Vec::new())],
            true,
        )],
        watermark: Some(IndexWatermark {
            height: 0,
            hash: [0x5a; 32],
        }),
        extra_blocks: Vec::new(),
        utxo_adds: Vec::new(),
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
        ranged_body: true,
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            prefix,
            vec![(tempting_row, Vec::new())],
            false,
        )],
        watermark: None,
        extra_blocks: Vec::new(),
        utxo_adds: Vec::new(),
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
        ranged_body: true,
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            prefix,
            vec![(indexed_row, Vec::new())],
            true,
        )],
        watermark: None,
        extra_blocks: Vec::new(),
        utxo_adds: Vec::new(),
    })?;

    assert!(matches!(
        fixture.engine.transaction(&txid),
        Err(TxQueryError::Unavailable(_))
    ));
    Ok(())
}

/// Body source that fails every read with a cloned error, proving read
/// failures surface as `Storage` rather than missing-body `Unavailable`.
struct FailingBody {
    error: bitcoin_rs_chain::BlockBodyReadError,
}

impl BlockBodySource for FailingBody {
    fn block_body(
        &self,
        _height: u32,
        _hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
        Err(self.error.clone())
    }
}

/// Body source that reports every body as absent, proving `Ok(None)` stays
/// missing-body `Unavailable` rather than becoming `Storage`.
struct MissingBody;

impl BlockBodySource for MissingBody {
    fn block_body(
        &self,
        _height: u32,
        _hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
        Ok(None)
    }
}

fn engine_with_body_source(
    block: &Block,
    scans: Vec<ScanResponse>,
    body_source: Option<Arc<dyn BlockBodySource>>,
) -> Result<DerivedIndexQueryEngine, Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let tip_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    let node = tree.node(tip_id)?;
    let tip = TipSnapshot {
        tip_id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
        chain_tx_count: node.chain_tx_count,
    };
    let tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    applied_tip.store(Some(Arc::new(tip.clone())));
    let chain_transition = bitcoin_rs_chain::TransitionDomain::new().stable_read();
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
    let reader = Arc::new(QueryReader {
        snapshot: QuerySnapshot {
            watermark: IndexWatermark {
                height: tip.height,
                hash: *tip.hash.as_byte_array(),
            },
            scans,
            funding_scans: Arc::new(AtomicUsize::new(0)),
            chain_transition: chain_transition.clone(),
        },
    });
    Ok(DerivedIndexQueryEngine::new(
        runtime,
        reader,
        bitcoin_rs_chain::BlockTreeReader::new(tree),
        bitcoin_rs_chain::TipReader::new(applied_tip),
        body_source,
        QueryEngineLive {
            utxo: None,
            chain_transition: Some(chain_transition),
            enabled: IndexCapabilities::ALL,
        },
    ))
}

fn engine_with_body_error(
    block: &Block,
    scans: Vec<ScanResponse>,
    error: bitcoin_rs_chain::BlockBodyReadError,
) -> Result<DerivedIndexQueryEngine, Box<dyn std::error::Error>> {
    engine_with_body_source(block, scans, Some(Arc::new(FailingBody { error })))
}

#[test]
fn transaction_reports_unavailable_when_body_source_returns_none()
-> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
    let prefix = TxidRow::scan_prefix(&txid);
    let indexed_row = TxidRow::row(&txid, 0).to_db_row().to_vec();
    let engine = engine_with_body_source(
        &block,
        vec![scan_response(
            ColumnFamily::TxConfirmed,
            prefix,
            vec![(indexed_row, Vec::new())],
            true,
        )],
        Some(Arc::new(MissingBody)),
    )?;

    assert!(matches!(
        engine.transaction(&txid),
        Err(TxQueryError::Unavailable(
            TxUnavailableCause::BlockBodyMissing { height: 0 }
        ))
    ));
    Ok(())
}

#[test]
fn transaction_reports_storage_when_body_read_fails() -> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
    let prefix = TxidRow::scan_prefix(&txid);
    let indexed_row = TxidRow::row(&txid, 0).to_db_row().to_vec();
    let engine = engine_with_body_error(
        &block,
        vec![scan_response(
            ColumnFamily::TxConfirmed,
            prefix,
            vec![(indexed_row, Vec::new())],
            true,
        )],
        bitcoin_rs_chain::BlockBodyReadError::Read("injected read failure".into()),
    )?;

    assert!(matches!(
        engine.transaction(&txid),
        Err(TxQueryError::Storage(_))
    ));
    Ok(())
}

#[test]
fn transaction_reports_storage_when_body_is_corrupt() -> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
    let prefix = TxidRow::scan_prefix(&txid);
    let indexed_row = TxidRow::row(&txid, 0).to_db_row().to_vec();
    let engine = engine_with_body_error(
        &block,
        vec![scan_response(
            ColumnFamily::TxConfirmed,
            prefix,
            vec![(indexed_row, Vec::new())],
            true,
        )],
        bitcoin_rs_chain::BlockBodyReadError::Corrupt("injected corruption".into()),
    )?;

    assert!(matches!(
        engine.transaction(&txid),
        Err(TxQueryError::Storage(_))
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
        ranged_body: true,
        scans: vec![scan_response(
            ColumnFamily::Spending,
            SpendingPrefixRow::scan_prefix(&outpoint),
            vec![(
                spending_row,
                TxPositionValue::encode(&[position_of_transaction(&block, 0)?]),
            )],
            true,
        )],
        watermark: None,
        extra_blocks: Vec::new(),
        utxo_adds: Vec::new(),
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

#[test]
fn complete_history_and_funding_share_one_durable_scan() -> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let transaction = &block.txs[0];
    let txid = transaction.txid();
    let script = crate::ScriptHash::new(&transaction.outputs[0].script_pubkey);
    let value = transaction.outputs[0].value.to_sat();
    let position = position_of_transaction(&block, 0)?;
    let row = HashPrefixRow::new(script.prefix(), 0);
    let occurrence = crate::types::ScriptHistoryOccurrence {
        scripthash: script,
        txid: *txid.as_bytes(),
        position,
        flags: crate::types::ScriptHistoryOccurrence::FUNDING,
    };
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        ranged_body: true,
        extra_blocks: Vec::new(),
        utxo_adds: Vec::new(),
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(script),
            vec![(
                zerocopy::IntoBytes::as_bytes(&row).to_vec(),
                crate::types::ScriptHistoryOccurrence::encode_all(&[occurrence]),
            )],
            true,
        )],
        watermark: None,
    })?;
    let snapshot = fixture.engine.history_snapshot(script)?;
    assert_eq!(
        snapshot.history,
        vec![crate::ScriptHistoryRecord { txid, height: 0 }]
    );
    assert_eq!(
        snapshot.funding,
        vec![crate::ScriptIndexRecord {
            txid,
            height: 0,
            value,
            vout: 0
        }]
    );
    assert_eq!(fixture.funding_scans.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn history_snapshot_falls_back_to_full_block_when_ranged_read_is_absent()
-> Result<(), Box<dyn std::error::Error>> {
    // A body source may leave `block_body_range` unimplemented; `None` asks
    // for the whole-body read rather than reporting the body missing.
    let block = Network::Regtest.genesis_block();
    let transaction = &block.txs[0];
    let txid = transaction.txid();
    let script = crate::ScriptHash::new(&transaction.outputs[0].script_pubkey);
    let value = transaction.outputs[0].value.to_sat();
    let position = position_of_transaction(&block, 0)?;
    let row = HashPrefixRow::new(script.prefix(), 0);
    let occurrence = crate::types::ScriptHistoryOccurrence {
        scripthash: script,
        txid: *txid.as_bytes(),
        position,
        flags: crate::types::ScriptHistoryOccurrence::FUNDING,
    };
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        ranged_body: false,
        extra_blocks: Vec::new(),
        utxo_adds: Vec::new(),
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(script),
            vec![(
                zerocopy::IntoBytes::as_bytes(&row).to_vec(),
                crate::types::ScriptHistoryOccurrence::encode_all(&[occurrence]),
            )],
            true,
        )],
        watermark: None,
    })?;
    let snapshot = fixture.engine.history_snapshot(script)?;
    assert_eq!(
        snapshot.funding,
        vec![crate::ScriptIndexRecord {
            txid,
            height: 0,
            value,
            vout: 0
        }]
    );
    assert_eq!(fixture.full_reads()?, 1);
    Ok(())
}

#[test]
fn confirmed_history_fetches_shared_block_once_per_query_and_refetches_next_query()
-> Result<(), Box<dyn std::error::Error>> {
    // One unified funding row carries both the funding and the spending
    // occurrence for the script, so `confirmed_history` needs no block read
    // at all: the occurrences already name every txid.
    let (block, _, scripthash, spend_txid) = block_with_spending_transaction()?;
    let funding_txid = block.txs[0].txid();
    let occurrences = crate::types::ScriptHistoryOccurrence::encode_all(&[
        crate::types::ScriptHistoryOccurrence {
            scripthash,
            txid: *funding_txid.as_bytes(),
            position: position_of_transaction(&block, 0)?,
            flags: crate::types::ScriptHistoryOccurrence::FUNDING,
        },
        crate::types::ScriptHistoryOccurrence {
            scripthash,
            txid: *spend_txid.as_bytes(),
            position: position_of_transaction(&block, 1)?,
            flags: crate::types::ScriptHistoryOccurrence::SPENDING,
        },
    ]);
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        ranged_body: true,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            vec![(
                ScriptHashRow::row(scripthash, 0).to_db_row().to_vec(),
                occurrences,
            )],
            true,
        )],
        watermark: None,
        extra_blocks: Vec::new(),
        utxo_adds: Vec::new(),
    })?;

    let history = fixture.engine.confirmed_history(scripthash)?;
    assert_eq!(history.len(), 2);
    assert!(
        history
            .iter()
            .any(|record| record.txid == funding_txid && record.height == 0)
    );
    assert!(
        history
            .iter()
            .any(|record| record.txid == spend_txid && record.height == 0)
    );
    assert_eq!(fixture.full_reads()?, 0);

    // A second public query stays read-free as well: the row value is the
    // authority, not a resolved block.
    let second = fixture.engine.confirmed_history(scripthash)?;
    assert_eq!(second.len(), 2);
    assert_eq!(fixture.full_reads()?, 0);
    Ok(())
}

struct MultiBlockBody {
    bodies: Vec<(u32, BlockHash, Vec<u8>)>,
    full_reads: AtomicUsize,
}

impl BlockBodySource for MultiBlockBody {
    fn block_body(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
        let hit = self
            .bodies
            .iter()
            .find(|(block_height, block_hash, _)| *block_height == height && *block_hash == hash);
        if hit.is_some() {
            self.full_reads.fetch_add(1, Ordering::Relaxed);
        }
        Ok(hit.map(|(_, _, body)| body.clone()))
    }

    fn block_body_range(
        &self,
        height: u32,
        hash: BlockHash,
        offset: u32,
        len: u32,
    ) -> Option<Vec<u8>> {
        let (_, _, body) = self
            .bodies
            .iter()
            .find(|(block_height, block_hash, _)| *block_height == height && *block_hash == hash)?;
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        body.get(start..end).map(<[u8]>::to_vec)
    }
}

fn seed_utxo_reader(
    adds: Vec<(OutPoint, TxOut, bool, u32)>,
    tip: Hash256,
) -> Result<Option<bitcoin_rs_utxo::UtxoReader>, Box<dyn std::error::Error>> {
    use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd, commit_block_changes};
    if adds.is_empty() {
        return Ok(None);
    }
    let set = Arc::new(bitcoin_rs_utxo::UtxoSet::new());
    let mut changes = BlockChanges::with_capacity(adds.len(), 0);
    for (outpoint, txout, coinbase, height) in adds {
        changes.add(UtxoAdd::new(outpoint, txout, coinbase, height));
    }
    commit_block_changes(&set, &changes, &tip)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    Ok(Some(bitcoin_rs_utxo::UtxoReader::new(set)))
}

fn child_block(parent: &Block, txs: Vec<Tx>) -> Result<Block, std::io::Error> {
    let mut block = parent.clone();
    block.header.prev_blockhash = parent.block_hash();
    block.txs = txs;
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| std::io::Error::other("chain test block carries transactions"))?;
    Ok(block)
}

/// Three-height chain paying one script: the genesis coinbase at height 0,
/// two outputs at height 1 in descending txid block order, one output at
/// height 2. Returns the genesis block, the two children, and the paid
/// script's hash.
fn paying_chain() -> Result<(Block, Vec<Block>, ScriptHash), std::io::Error> {
    let genesis = Network::Regtest.genesis_block();
    let script = genesis.txs[0].outputs[0].script_pubkey.clone();
    let value = genesis.txs[0].outputs[0].value;
    let pay = |filler: &[u8]| Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: {
            let mut outputs = vec![TxOut {
                value,
                script_pubkey: script.clone(),
            }];
            if !filler.is_empty() {
                outputs.push(TxOut {
                    value,
                    script_pubkey: Script::from_bytes(filler.to_vec()),
                });
            }
            outputs
        },
    };
    let mut middle_txs = vec![pay(&[0x6a, 0x01]), pay(&[0x6a, 0x02])];
    middle_txs.sort_by_key(|tx| std::cmp::Reverse(tx.txid()));
    let middle = child_block(&genesis, middle_txs)?;
    let tip = child_block(&middle, vec![pay(&[])])?;
    let scripthash = ScriptHash::new(&script);
    Ok((genesis, vec![middle, tip], scripthash))
}

#[test]
fn outpoint_value_returns_confirmed_output_value() -> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
    let expected = block.txs[0].outputs[0].value.to_sat();
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        ranged_body: true,
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            TxidRow::scan_prefix(&txid),
            vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), Vec::new())],
            true,
        )],
        watermark: None,
        extra_blocks: Vec::new(),
        utxo_adds: Vec::new(),
    })?;

    assert_eq!(
        fixture.engine.outpoint_value(&OutPoint { txid, vout: 0 })?,
        Some(expected)
    );
    Ok(())
}

#[test]
fn outpoint_value_returns_none_for_out_of_range_vout() -> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
    let vout = u32::try_from(block.txs[0].outputs.len())
        .map_err(|_| std::io::Error::other("vout fits"))?;
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        ranged_body: true,
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            TxidRow::scan_prefix(&txid),
            vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), Vec::new())],
            true,
        )],
        watermark: None,
        extra_blocks: Vec::new(),
        utxo_adds: Vec::new(),
    })?;

    assert_eq!(
        fixture.engine.outpoint_value(&OutPoint { txid, vout })?,
        None
    );
    Ok(())
}

#[test]
fn outpoint_value_returns_none_for_unknown_txid() -> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let known = block.txs[0].txid();
    let unknown = Txid(Hash256::from_le_bytes(&[0xa5; 32]));
    assert_ne!(known.as_bytes(), &[0xa5; 32]);
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        ranged_body: true,
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            TxidRow::scan_prefix(&unknown),
            Vec::new(),
            true,
        )],
        watermark: None,
        extra_blocks: Vec::new(),
        utxo_adds: Vec::new(),
    })?;

    // A complete scan with no rows proves the index holds nothing for this
    // txid, so the value query answers None instead of Retry or Unavailable.
    assert_eq!(
        fixture.engine.outpoint_value(&OutPoint {
            txid: unknown,
            vout: 0,
        })?,
        None
    );
    Ok(())
}

#[test]
fn funding_prefix_scan_ignores_outputs_paying_other_scripts()
-> Result<(), Box<dyn std::error::Error>> {
    // The funding row is filed under the requested scripthash's prefix, yet
    // its positioned transaction pays a different script: the row is a
    // prefix match only, exactly what an 8-byte prefix collision yields.
    // `collect_funding_outputs` must keep it out via the full ScriptHash
    // compare while the full-block fallback still finds the real output.
    let (block, _, scripthash, _) = block_with_spending_transaction()?;
    // A row under the queried scripthash's 8-byte prefix can hold occurrences
    // for another scripthash — the collision shape format 6 exists to filter.
    let foreign = crate::types::ScriptHistoryOccurrence {
        scripthash: crate::ScriptHash::new(&block.txs[1].outputs[0].script_pubkey),
        txid: *block.txs[1].txid().as_bytes(),
        position: position_of_transaction(&block, 1)?,
        flags: crate::types::ScriptHistoryOccurrence::FUNDING,
    };
    let real = crate::types::ScriptHistoryOccurrence {
        scripthash,
        txid: *block.txs[0].txid().as_bytes(),
        position: position_of_transaction(&block, 0)?,
        flags: crate::types::ScriptHistoryOccurrence::FUNDING,
    };
    let funding_txid = block.txs[0].txid();
    let expected_value = block.txs[0].outputs[0].value.to_sat();
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        ranged_body: true,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            vec![(
                ScriptHashRow::row(scripthash, 0).to_db_row().to_vec(),
                crate::types::ScriptHistoryOccurrence::encode_all(&[foreign, real]),
            )],
            true,
        )],
        watermark: None,
        extra_blocks: Vec::new(),
        utxo_adds: Vec::new(),
    })?;

    let history = fixture.engine.confirmed_history(scripthash)?;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].txid, funding_txid);
    assert_eq!(history[0].height, 0);
    let snapshot = fixture.engine.history_snapshot(scripthash)?;
    assert_eq!(snapshot.funding.len(), 1);
    assert_eq!(snapshot.funding[0].txid, funding_txid);
    assert_eq!(snapshot.funding[0].vout, 0);
    assert_eq!(snapshot.funding[0].height, 0);
    assert_eq!(snapshot.funding[0].value, expected_value);
    Ok(())
}

#[test]
fn live_prefix_scan_ignores_coins_paying_other_scripts() -> Result<(), Box<dyn std::error::Error>> {
    // Both live rows sit under the requested scripthash's prefix, but the
    // authoritative coin behind `foreign` pays a different script: the exact
    // script check in `unspent_outputs_for` must filter it while keeping the
    // real coin.
    let (block, _, scripthash, _) = block_with_spending_transaction()?;
    let real = OutPoint {
        txid: block.txs[0].txid(),
        vout: 0,
    };
    let foreign = OutPoint {
        txid: block.txs[1].txid(),
        vout: 0,
    };
    let real_txout = block.txs[0].outputs[0].clone();
    let foreign_txout = block.txs[1].outputs[0].clone();
    let real_txid = real.txid;
    let expected_value = real_txout.value.to_sat();
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        ranged_body: true,
        scans: vec![scan_response(
            ColumnFamily::ScriptLive,
            ScriptHashRow::scan_prefix(scripthash),
            vec![
                (
                    ScriptLiveRow::new(scripthash, &foreign).as_bytes().to_vec(),
                    Vec::new(),
                ),
                (
                    ScriptLiveRow::new(scripthash, &real).as_bytes().to_vec(),
                    Vec::new(),
                ),
            ],
            true,
        )],
        watermark: None,
        extra_blocks: Vec::new(),
        utxo_adds: vec![
            (real, real_txout, true, 0),
            (foreign, foreign_txout, false, 0),
        ],
    })?;

    let unspent = fixture.engine.unspent_outputs(scripthash)?;
    assert_eq!(unspent.len(), 1);
    assert_eq!(unspent[0].txid, real_txid);
    assert_eq!(unspent[0].vout, 0);
    assert_eq!(unspent[0].height, 0);
    assert_eq!(unspent[0].value, expected_value);
    Ok(())
}

#[test]
fn confirmed_history_orders_funding_rows_by_height_then_txid()
-> Result<(), Box<dyn std::error::Error>> {
    // Funding rows arrive in non-ascending height order; the engine must
    // return them sorted by the (height, txid) key from scripts.rs. Height 1
    // holds two outputs in descending txid block order to pin the txid half
    // of the key.
    let (genesis, chain, scripthash) = paying_chain()?;
    let mut funded: Vec<(u32, Txid)> = vec![(0, genesis.txs[0].txid())];
    for tx in &chain[1].txs {
        funded.push((2, tx.txid()));
    }
    for tx in &chain[0].txs {
        funded.push((1, tx.txid()));
    }
    funded.sort();
    let occurrences = |block: &Block, _height: u32| -> Result<_, std::io::Error> {
        let mut entries = Vec::new();
        for (index, tx) in block.txs.iter().enumerate() {
            entries.push(crate::types::ScriptHistoryOccurrence {
                scripthash,
                txid: *tx.txid().as_bytes(),
                position: position_of_transaction(block, index)?,
                flags: crate::types::ScriptHistoryOccurrence::FUNDING,
            });
        }
        Ok(crate::types::ScriptHistoryOccurrence::encode_all(&entries))
    };
    let rows = [
        (2, occurrences(&chain[1], 2)?),
        (0, occurrences(&genesis, 0)?),
        (1, occurrences(&chain[0], 1)?),
    ];
    let fixture = QueryFixture::new(FixtureConfig {
        block: genesis,
        retain_body: true,
        ranged_body: true,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            rows.iter()
                .map(|(height, value)| {
                    (
                        ScriptHashRow::row(scripthash, *height).to_db_row().to_vec(),
                        value.clone(),
                    )
                })
                .collect(),
            true,
        )],
        watermark: None,
        extra_blocks: chain,
        utxo_adds: Vec::new(),
    })?;

    let history = fixture.engine.confirmed_history(scripthash)?;
    assert_eq!(history.len(), funded.len());
    for (record, (height, txid)) in history.iter().zip(funded.iter()) {
        assert_eq!(record.height, *height);
        assert_eq!(record.txid, *txid);
    }
    let snapshot = fixture.engine.history_snapshot(scripthash)?;
    assert_eq!(snapshot.funding.len(), funded.len());
    for (record, (height, txid)) in snapshot.funding.iter().zip(funded.iter()) {
        assert_eq!(record.height, *height);
        assert_eq!(record.txid, *txid);
        assert_eq!(record.vout, 0);
    }
    Ok(())
}

#[test]
fn unspent_outputs_orders_live_rows_by_height_then_txid() -> Result<(), Box<dyn std::error::Error>>
{
    // Live rows arrive in non-ascending height order; the engine must return
    // them sorted by the (height, txid, vout) key from scripts.rs. Coin
    // heights come from the seeded UTXO view, not the row keys.
    let (genesis, chain, scripthash) = paying_chain()?;
    let coin_value = genesis.txs[0].outputs[0].value.to_sat();
    let mut coins: Vec<(u32, OutPoint, TxOut)> = Vec::new();
    for tx in &chain[1].txs {
        coins.push((2, OutPoint::new(tx.txid(), 0), tx.outputs[0].clone()));
    }
    coins.push((
        0,
        OutPoint::new(genesis.txs[0].txid(), 0),
        genesis.txs[0].outputs[0].clone(),
    ));
    for tx in &chain[0].txs {
        coins.push((1, OutPoint::new(tx.txid(), 0), tx.outputs[0].clone()));
    }
    let rows = coins
        .iter()
        .map(|(_, outpoint, _)| {
            (
                ScriptLiveRow::new(scripthash, outpoint).as_bytes().to_vec(),
                Vec::new(),
            )
        })
        .collect::<Vec<_>>();
    let seeds = coins
        .iter()
        .map(|(height, outpoint, txout)| (*outpoint, txout.clone(), false, *height))
        .collect::<Vec<_>>();
    let mut expected: Vec<(u32, Txid, u32)> = coins
        .iter()
        .map(|(height, outpoint, _)| (*height, outpoint.txid, outpoint.vout))
        .collect();
    expected.sort();
    let fixture = QueryFixture::new(FixtureConfig {
        block: genesis,
        retain_body: true,
        ranged_body: true,
        scans: vec![scan_response(
            ColumnFamily::ScriptLive,
            ScriptHashRow::scan_prefix(scripthash),
            rows,
            true,
        )],
        watermark: None,
        extra_blocks: chain,
        utxo_adds: seeds,
    })?;

    let unspent = fixture.engine.unspent_outputs(scripthash)?;
    assert_eq!(unspent.len(), expected.len());
    for (record, (height, txid, vout)) in unspent.iter().zip(expected.iter()) {
        assert_eq!(record.height, *height);
        assert_eq!(record.txid, *txid);
        assert_eq!(record.vout, *vout);
        assert_eq!(record.value, coin_value);
    }
    Ok(())
}

#[test]
fn confirmed_history_with_nonmatching_script_falls_back_per_height_and_stays_empty()
-> Result<(), Box<dyn std::error::Error>> {
    // Hostile shape from the finding: one unauthenticated scripthash query
    // fans out to rows at several candidate heights. Under format 6 each row
    // self-describes its occurrences, so rows filed under the queried prefix
    // whose occurrences name a different scripthash are filtered without a
    // single block read.
    let (genesis, chain, scripthash) = paying_chain()?;
    let foreign = ScriptHash::new(&Script::from_bytes(vec![0x51, 0x41, 0x42]));
    let occurrences = |block: &Block| -> Result<_, std::io::Error> {
        let mut entries = Vec::new();
        for (index, tx) in block.txs.iter().enumerate() {
            entries.push(crate::types::ScriptHistoryOccurrence {
                scripthash,
                txid: *tx.txid().as_bytes(),
                position: position_of_transaction(block, index)?,
                flags: crate::types::ScriptHistoryOccurrence::FUNDING,
            });
        }
        Ok(crate::types::ScriptHistoryOccurrence::encode_all(&entries))
    };
    let rows = [
        (2, occurrences(&chain[1])?),
        (0, occurrences(&genesis)?),
        (1, occurrences(&chain[0])?),
    ];
    let fixture = QueryFixture::new(FixtureConfig {
        block: genesis,
        retain_body: true,
        ranged_body: true,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(foreign),
            rows.iter()
                .map(|(height, value)| {
                    (
                        ScriptHashRow::row(foreign, *height).to_db_row().to_vec(),
                        value.clone(),
                    )
                })
                .collect(),
            true,
        )],
        watermark: None,
        extra_blocks: chain,
        utxo_adds: Vec::new(),
    })?;

    let history = fixture.engine.confirmed_history(foreign)?;
    assert_eq!(history.len(), 0);
    assert_eq!(fixture.full_reads()?, 0);

    let second = fixture.engine.confirmed_history(foreign)?;
    assert_eq!(second.len(), 0);
    assert_eq!(fixture.full_reads()?, 0);
    Ok(())
}
