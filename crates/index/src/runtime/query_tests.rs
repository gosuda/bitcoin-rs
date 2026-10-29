use crate::TxIndexSnapshot;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::types::{TxPosition, TxPositionValue, TxidRow};
use crate::{HashPrefixRow, IndexCapabilities, ScriptHashRow, ScriptLiveRow, SpendingPrefixRow};
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{NodeStatus, regtest_fixture};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid,
    Witness, consensus_bytes,
};
use bitcoin_rs_storage::{ColumnFamily, PrefixScan, PrefixScanLimit};

use super::*;
use crate::query_api::{HistoricalQueryError, HistoricalUnavailableCause};
use crate::{IndexCapability, IndexWatermark};
use bitcoin_rs_chain::{BlockTree, NodeId};
use parking_lot::Mutex as ParkMutex;

#[derive(Clone)]
struct ScanResponse {
    cf: ColumnFamily,
    prefix: Vec<u8>,
    scan: PrefixScan,
}

fn fake_family_page(
    scans: &[ScanResponse],
    cf: ColumnFamily,
    start_after: Option<&[u8]>,
    limit: PrefixScanLimit,
) -> Result<crate::TxIndexPage, IndexError> {
    let mut rows: Vec<_> = scans
        .iter()
        .filter(|response| response.cf == cf)
        .flat_map(|response| response.scan.rows.iter().cloned())
        .collect();
    rows.sort();
    rows.dedup_by(|left, right| left.0 == right.0);
    let mut page = Vec::new();
    let mut bytes = 0_usize;
    for (key, value) in rows {
        if start_after.is_some_and(|cursor| key.as_slice() <= cursor) {
            continue;
        }
        let row_bytes = key.len() + value.len();
        if page.len() >= limit.max_rows
            || (!page.is_empty() && bytes.saturating_add(row_bytes) > limit.max_bytes)
        {
            return Ok(crate::TxIndexPage {
                rows: page,
                complete: false,
            });
        }
        bytes = bytes.saturating_add(row_bytes);
        if key.len() != crate::HASH_PREFIX_ROW_SIZE {
            return Err(IndexError::InvalidPrefixRowLength { len: key.len() });
        }
        let row = zerocopy::FromBytes::read_from_bytes(&key)
            .map_err(|_| IndexError::InvalidPrefixRowLength { len: key.len() })?;
        page.push(TxIndexScanRow { row, value });
    }
    Ok(crate::TxIndexPage {
        rows: page,
        complete: true,
    })
}

#[derive(Clone)]
struct QuerySnapshot {
    watermark: IndexWatermark,
    scans: Vec<ScanResponse>,
    chain_transition: bitcoin_rs_chain::StableRead,
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

    fn scan_family_page(
        &self,
        family: crate::TxIndexFamily,
        start_after: Option<&[u8]>,
        limit: PrefixScanLimit,
    ) -> Result<crate::TxIndexPage, IndexError> {
        let cf = match family {
            crate::TxIndexFamily::TxConfirmed => ColumnFamily::TxConfirmed,
        };
        fake_family_page(&self.scans, cf, start_after, limit)
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
    scans: Vec<ScanResponse>,
    watermark: Option<IndexWatermark>,
    extra_blocks: Vec<Block>,
    /// `(outpoint, txout, coinbase, height)`. Empty leaves the engine
    utxo_adds: Vec<(OutPoint, TxOut, bool, u32)>,
}

struct QueryFixture {
    engine: DerivedIndexQueryEngine,
    runtime: Arc<DerivedIndexRuntime>,
    body: Option<Arc<SingleBlockBody>>,
    multi_body: Option<Arc<MultiBlockBody>>,
}

pub(super) struct SingleBlockBody {
    pub(super) height: u32,
    pub(super) hash: BlockHash,
    pub(super) body: Vec<u8>,
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
        if height != self.height || hash != self.hash {
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
        let reader = Arc::new(QueryReader {
            snapshot: QuerySnapshot {
                watermark,
                scans: config.scans,
                chain_transition: chain_transition.clone(),
            },
        });
        let body = if config.retain_body && blocks.len() == 1 {
            Some(Arc::new(SingleBlockBody {
                height: heights[0],
                hash: blocks[0].block_hash(),
                body: consensus_bytes(&blocks[0]),
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
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            TxidRow::scan_prefix(&txid),
            vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
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
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            prefix,
            vec![(indexed_row, vec![0])],
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
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            prefix,
            vec![(tempting_row, vec![0])],
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
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            prefix,
            vec![(indexed_row, vec![0])],
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
            vec![(indexed_row, vec![0])],
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
            vec![(indexed_row, vec![0])],
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
            vec![(indexed_row, vec![0])],
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
fn empty_position_rows_are_refused_before_body_reads() -> Result<(), Box<dyn std::error::Error>> {
    let (block, outpoint, scripthash, _) = block_with_spending_transaction()?;
    let txid = block.txs[0].txid();
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        scans: vec![
            scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&txid),
                vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), Vec::new())],
                true,
            ),
            scan_response(
                ColumnFamily::Funding,
                ScriptHashRow::scan_prefix(scripthash),
                vec![(
                    ScriptHashRow::row(scripthash, 0).to_db_row().to_vec(),
                    Vec::new(),
                )],
                true,
            ),
            scan_response(
                ColumnFamily::Spending,
                SpendingPrefixRow::scan_prefix(&outpoint),
                vec![(
                    SpendingPrefixRow::row(&outpoint, 0).to_db_row().to_vec(),
                    Vec::new(),
                )],
                true,
            ),
        ],
        watermark: None,
        extra_blocks: Vec::new(),
        utxo_adds: Vec::new(),
    })?;
    assert!(matches!(
        fixture.engine.transaction(&txid),
        Err(TxQueryError::Storage(_))
    ));
    assert!(matches!(
        fixture.engine.confirmed_history(scripthash),
        Err(TxQueryError::Storage(_))
    ));
    assert!(matches!(
        fixture.engine.spender(outpoint),
        Err(TxQueryError::Storage(_))
    ));
    assert_eq!(fixture.full_reads()?, 0);
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
fn confirmed_history_fetches_shared_block_once_per_query_and_refetches_next_query()
-> Result<(), Box<dyn std::error::Error>> {
    let (block, outpoint, scripthash, spend_txid) = block_with_spending_transaction()?;
    let funding_txid = block.txs[0].txid();
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        scans: vec![
            scan_response(
                ColumnFamily::Funding,
                ScriptHashRow::scan_prefix(scripthash),
                vec![(
                    ScriptHashRow::row(scripthash, 0).to_db_row().to_vec(),
                    vec![0],
                )],
                true,
            ),
            scan_response(
                ColumnFamily::Spending,
                SpendingPrefixRow::scan_prefix(&outpoint),
                vec![(
                    SpendingPrefixRow::row(&outpoint, 0).to_db_row().to_vec(),
                    vec![0],
                )],
                true,
            ),
        ],
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
    assert_eq!(fixture.full_reads()?, 1);

    let second = fixture.engine.confirmed_history(scripthash)?;
    assert_eq!(second.len(), 2);
    assert_eq!(fixture.full_reads()?, 2);
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

/// Three-height chain paying one script: the genesis coinbase at height 0, two outputs
/// at height 1 in descending txid block order, one output at height 2.
///
/// Returns the genesis block, the two children, and the paid
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
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            TxidRow::scan_prefix(&txid),
            vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
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
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            TxidRow::scan_prefix(&txid),
            vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
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
    let (block, _, scripthash, _) = block_with_spending_transaction()?;
    let foreign = position_of_transaction(&block, 1)?;
    let funding_txid = block.txs[0].txid();
    let expected_value = block.txs[0].outputs[0].value.to_sat();
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            vec![(
                ScriptHashRow::row(scripthash, 0).to_db_row().to_vec(),
                TxPositionValue::encode(&[foreign]),
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
    let (genesis, chain, scripthash) = paying_chain()?;
    let mut funded: Vec<(u32, Txid)> = vec![(0, genesis.txs[0].txid())];
    for tx in &chain[1].txs {
        funded.push((2, tx.txid()));
    }
    for tx in &chain[0].txs {
        funded.push((1, tx.txid()));
    }
    funded.sort();
    let fixture = QueryFixture::new(FixtureConfig {
        block: genesis,
        retain_body: true,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            vec![
                (
                    ScriptHashRow::row(scripthash, 2).to_db_row().to_vec(),
                    vec![0],
                ),
                (
                    ScriptHashRow::row(scripthash, 0).to_db_row().to_vec(),
                    vec![0],
                ),
                (
                    ScriptHashRow::row(scripthash, 1).to_db_row().to_vec(),
                    vec![0],
                ),
            ],
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
    let (genesis, chain, _) = paying_chain()?;
    let foreign = ScriptHash::new(&Script::from_bytes(vec![0x51, 0x41, 0x42]));
    let fixture = QueryFixture::new(FixtureConfig {
        block: genesis,
        retain_body: true,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(foreign),
            vec![
                (ScriptHashRow::row(foreign, 2).to_db_row().to_vec(), vec![0]),
                (ScriptHashRow::row(foreign, 0).to_db_row().to_vec(), vec![0]),
                (ScriptHashRow::row(foreign, 1).to_db_row().to_vec(), vec![0]),
            ],
            true,
        )],
        watermark: None,
        extra_blocks: chain,
        utxo_adds: Vec::new(),
    })?;

    let history = fixture.engine.confirmed_history(foreign)?;
    assert_eq!(history.len(), 0);
    assert_eq!(fixture.full_reads()?, 3);

    let second = fixture.engine.confirmed_history(foreign)?;
    assert_eq!(second.len(), 0);
    assert_eq!(fixture.full_reads()?, 6);
    Ok(())
}

#[derive(Clone)]
struct HistoricalSnapshot {
    tx_watermark: Option<IndexWatermark>,
    sh_watermark: Option<IndexWatermark>,
    tx_floor: u32,
    sh_floor: u32,
    scans: Vec<ScanResponse>,
}

impl HistoricalSnapshot {
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
            let prefix_bytes: [u8; 8] = key[..crate::types::HASH_PREFIX_LEN]
                .try_into()
                .map_err(|_| IndexError::InvalidPrefixRowLength { len: key.len() })?;
            let height_bytes: [u8; 4] = key
                [crate::types::HASH_PREFIX_LEN..crate::HASH_PREFIX_ROW_SIZE]
                .try_into()
                .map_err(|_| IndexError::InvalidPrefixRowLength { len: key.len() })?;
            rows.push(TxIndexScanRow {
                row: HashPrefixRow {
                    prefix: prefix_bytes,
                    height: height_bytes,
                },
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

impl TxIndexSnapshot for HistoricalSnapshot {
    fn capability_watermark(
        &self,
        capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        match capability {
            IndexCapability::TxLookup => Ok(self.tx_watermark),
            IndexCapability::ScriptHistory => Ok(self.sh_watermark),
            _ => Ok(None),
        }
    }

    fn capability_floor(&self, capability: IndexCapability) -> Result<u32, IndexError> {
        match capability {
            IndexCapability::TxLookup => Ok(self.tx_floor),
            IndexCapability::ScriptHistory => Ok(self.sh_floor),
            _ => Ok(0),
        }
    }

    fn scan_family_page(
        &self,
        family: crate::TxIndexFamily,
        start_after: Option<&[u8]>,
        limit: PrefixScanLimit,
    ) -> Result<crate::TxIndexPage, IndexError> {
        let cf = match family {
            crate::TxIndexFamily::TxConfirmed => ColumnFamily::TxConfirmed,
        };
        fake_family_page(&self.scans, cf, start_after, limit)
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
        _scripthash: ScriptHash,
        _limit: PrefixScanLimit,
    ) -> Result<crate::ScriptLiveScan, IndexError> {
        Ok(crate::ScriptLiveScan {
            rows: Vec::new(),
            encoded_bytes: 0,
            complete: true,
        })
    }
}

struct HistoricalReader {
    snapshot: HistoricalSnapshot,
}

impl IndexReader for HistoricalReader {
    fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError> {
        Ok(Box::new(self.snapshot.clone()))
    }
}

struct ResetReader {
    state: Arc<ParkMutex<HistoricalSnapshot>>,
}

impl IndexReader for ResetReader {
    fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError> {
        Ok(Box::new(self.state.lock().clone()))
    }
}

struct MovingBody {
    bodies: Vec<(u32, BlockHash, Vec<u8>)>,
    full_reads: AtomicUsize,
    on_first_read: ParkMutex<Option<Box<dyn Fn() + Send>>>,
}

impl MovingBody {
    fn new(
        bodies: Vec<(u32, BlockHash, Vec<u8>)>,
        on_first_read: Option<Box<dyn Fn() + Send>>,
    ) -> Self {
        Self {
            bodies,
            full_reads: AtomicUsize::new(0),
            on_first_read: ParkMutex::new(on_first_read),
        }
    }

    fn fire_once(&self) {
        let taken = self.on_first_read.lock().take();
        if let Some(callback) = taken {
            callback();
        }
    }

    fn lookup(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
        self.bodies
            .iter()
            .find(|(h, hh, _)| *h == height && *hh == hash)
            .map(|(_, _, body)| body.clone())
    }
}

impl BlockBodySource for MovingBody {
    fn block_body(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_chain::BlockBodyReadError> {
        self.fire_once();
        let hit = self.lookup(height, hash);
        if hit.is_some() {
            self.full_reads.fetch_add(1, Ordering::Relaxed);
        }
        Ok(hit)
    }

    fn block_body_range(
        &self,
        height: u32,
        hash: BlockHash,
        offset: u32,
        len: u32,
    ) -> Option<Vec<u8>> {
        self.fire_once();
        let (_, _, body) = self
            .bodies
            .iter()
            .find(|(h, hh, _)| *h == height && *hh == hash)?;
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        body.get(start..end).map(<[u8]>::to_vec)
    }
}

struct HistoricalFixture {
    engine: DerivedIndexQueryEngine,
    runtime: Arc<DerivedIndexRuntime>,
}

fn tip_snapshot_for(
    tree: &BlockTree,
    tip_id: NodeId,
) -> Result<TipSnapshot, Box<dyn std::error::Error>> {
    let node = tree.node(tip_id)?;
    Ok(TipSnapshot {
        tip_id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
        chain_tx_count: node.chain_tx_count,
    })
}

fn watermark_for(
    tree: &BlockTree,
    node_id: NodeId,
) -> Result<IndexWatermark, Box<dyn std::error::Error>> {
    let node = tree.node(node_id)?;
    Ok(IndexWatermark {
        height: node.height,
        hash: *node.hash.as_byte_array(),
    })
}

struct HistoricalConfig {
    tx_watermark: Option<IndexWatermark>,
    sh_watermark: Option<IndexWatermark>,
    tx_floor: u32,
    sh_floor: u32,
    scans: Vec<ScanResponse>,
    bodies: Vec<(u32, BlockHash, Vec<u8>)>,
    on_first_read: Option<Box<dyn Fn() + Send>>,
    enabled: IndexCapabilities,
}

impl HistoricalFixture {
    fn build(
        tree: BlockTree,
        tip_id: NodeId,
        config: HistoricalConfig,
    ) -> Result<(Self, Arc<MovingBody>), Box<dyn std::error::Error>> {
        let HistoricalConfig {
            tx_watermark,
            sh_watermark,
            tx_floor,
            sh_floor,
            scans,
            bodies,
            on_first_read,
            enabled,
        } = config;
        let tip = tip_snapshot_for(&tree, tip_id)?;
        let tree = Arc::new(RwLock::new(tree));
        let tip_cell = Arc::new(ArcSwapOption::empty());
        tip_cell.store(Some(Arc::new(tip)));
        let chain_transition = bitcoin_rs_chain::TransitionDomain::new().stable_read();
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
        let reader = Arc::new(HistoricalReader {
            snapshot: HistoricalSnapshot {
                tx_watermark,
                sh_watermark,
                tx_floor,
                sh_floor,
                scans,
            },
        });
        let body = Arc::new(MovingBody::new(bodies, on_first_read));
        let body_source: Option<Arc<dyn BlockBodySource>> = Some(body.clone());
        let engine = DerivedIndexQueryEngine::new(
            Arc::clone(&runtime),
            reader,
            bitcoin_rs_chain::BlockTreeReader::new(Arc::clone(&tree)),
            bitcoin_rs_chain::TipReader::new(Arc::clone(&tip_cell)),
            body_source,
            QueryEngineLive {
                utxo: None,
                chain_transition: Some(chain_transition),
                enabled,
            },
        );
        let fixture = Self { engine, runtime };
        Ok((fixture, body))
    }
}

#[test]
fn historical_extension_during_read_keeps_same_anchor() -> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
    let tip_block = child_block(&block, vec![block.txs[0].clone()])?;
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    let tip_id = tree.insert_header(tip_block.header, NodeStatus::HeaderValid)?;
    let genesis_watermark = watermark_for(&tree, genesis_id)?;
    let tip_snapshot = tip_snapshot_for(&tree, tip_id)?;
    let extension_block = child_block(&tip_block, vec![tip_block.txs[0].clone()])?;
    let extension_id = tree.insert_header(extension_block.header, NodeStatus::HeaderValid)?;
    let extension_tip = tip_snapshot_for(&tree, extension_id)?;
    let bodies = vec![(0, block.block_hash(), consensus_bytes(&block))];
    let tip_cell = Arc::new(ArcSwapOption::empty());
    tip_cell.store(Some(Arc::new(tip_snapshot)));
    let tip_cell_clone = Arc::clone(&tip_cell);
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
    let runtime_clone = Arc::clone(&runtime);
    let on_read: Option<Box<dyn Fn() + Send>> = Some(Box::new(move || {
        tip_cell_clone.store(Some(Arc::new(extension_tip.clone())));
        runtime_clone.wake();
    }));
    let body = Arc::new(MovingBody::new(bodies, on_read));
    let chain_transition = bitcoin_rs_chain::TransitionDomain::new().stable_read();
    let reader = Arc::new(HistoricalReader {
        snapshot: HistoricalSnapshot {
            tx_watermark: Some(genesis_watermark),
            sh_watermark: Some(genesis_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&txid),
                vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
                true,
            )],
        },
    });
    let engine = DerivedIndexQueryEngine::new(
        Arc::clone(&runtime),
        reader,
        bitcoin_rs_chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        bitcoin_rs_chain::TipReader::new(tip_cell),
        Some(body),
        QueryEngineLive {
            utxo: None,
            chain_transition: Some(chain_transition),
            enabled: IndexCapabilities::ALL,
        },
    );
    let at = engine.transaction_at_prefix(&txid)?;
    assert_eq!(at.prefix.height, 0);
    assert_eq!(at.prefix.floor, 0);
    assert!(at.answer.is_some());
    Ok(())
}

#[test]
fn historical_wake_without_tip_move_stays_valid_while_strict_retries()
-> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    let genesis_watermark = watermark_for(&tree, genesis_id)?;
    let tip_snapshot = tip_snapshot_for(&tree, genesis_id)?;
    let tip_cell = Arc::new(ArcSwapOption::empty());
    tip_cell.store(Some(Arc::new(tip_snapshot)));
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
    let runtime_clone = Arc::clone(&runtime);
    let on_read: Option<Box<dyn Fn() + Send>> = Some(Box::new(move || runtime_clone.wake()));
    let body = Arc::new(MovingBody::new(
        vec![(0, block.block_hash(), consensus_bytes(&block))],
        on_read,
    ));
    let chain_transition = bitcoin_rs_chain::TransitionDomain::new().stable_read();
    let reader: Arc<dyn IndexReader> = Arc::new(HistoricalReader {
        snapshot: HistoricalSnapshot {
            tx_watermark: Some(genesis_watermark),
            sh_watermark: Some(genesis_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&txid),
                vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
                true,
            )],
        },
    });
    let strict_reader: Arc<dyn IndexReader> = Arc::new(QueryReader {
        snapshot: QuerySnapshot {
            watermark: genesis_watermark,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&txid),
                vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
                true,
            )],
            chain_transition: chain_transition.clone(),
        },
    });
    let tree_handle = Arc::new(RwLock::new(tree));
    let historical = DerivedIndexQueryEngine::new(
        Arc::clone(&runtime),
        reader,
        bitcoin_rs_chain::BlockTreeReader::new(Arc::clone(&tree_handle)),
        bitcoin_rs_chain::TipReader::new(Arc::clone(&tip_cell)),
        Some(body),
        QueryEngineLive {
            utxo: None,
            chain_transition: Some(chain_transition.clone()),
            enabled: IndexCapabilities::ALL,
        },
    );
    let at = historical.transaction_at_prefix(&txid)?;
    assert_eq!(at.prefix.height, 0);
    assert!(at.answer.is_some());
    let runtime_clone = Arc::clone(&runtime);
    let strict_body = Arc::new(MovingBody::new(
        vec![(0, block.block_hash(), consensus_bytes(&block))],
        Some(Box::new(move || runtime_clone.wake())),
    ));
    let strict = DerivedIndexQueryEngine::new(
        runtime,
        strict_reader,
        bitcoin_rs_chain::BlockTreeReader::new(tree_handle),
        bitcoin_rs_chain::TipReader::new(tip_cell),
        Some(strict_body),
        QueryEngineLive {
            utxo: None,
            chain_transition: Some(chain_transition),
            enabled: IndexCapabilities::ALL,
        },
    );
    assert!(matches!(
        strict.transaction(&txid),
        Err(TxQueryError::Retry)
    ));
    Ok(())
}

#[test]
fn historical_reorg_above_anchor_stays_valid() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let txid = genesis.txs[0].txid();
    let main_child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
    let side_child = {
        let mut tx = genesis.txs[0].clone();
        tx.outputs[0].value = tx.outputs[0].value.saturating_add(Amount::from_sat(1));
        child_block(&genesis, vec![tx])?
    };
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    let main_id = tree.insert_header(main_child.header, NodeStatus::HeaderValid)?;
    let side_id = tree.insert_header(side_child.header, NodeStatus::HeaderValid)?;
    let genesis_watermark = watermark_for(&tree, genesis_id)?;
    let main_tip = tip_snapshot_for(&tree, main_id)?;
    let side_tip = tip_snapshot_for(&tree, side_id)?;
    let tip_cell = Arc::new(ArcSwapOption::empty());
    tip_cell.store(Some(Arc::new(main_tip)));
    let tip_cell_clone = Arc::clone(&tip_cell);
    let on_read: Option<Box<dyn Fn() + Send>> = Some(Box::new(move || {
        tip_cell_clone.store(Some(Arc::new(side_tip.clone())));
    }));
    let body = Arc::new(MovingBody::new(
        vec![(0, genesis.block_hash(), consensus_bytes(&genesis))],
        on_read,
    ));
    let chain_transition = bitcoin_rs_chain::TransitionDomain::new().stable_read();
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
    let reader = Arc::new(HistoricalReader {
        snapshot: HistoricalSnapshot {
            tx_watermark: Some(genesis_watermark),
            sh_watermark: Some(genesis_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&txid),
                vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
                true,
            )],
        },
    });
    let engine = DerivedIndexQueryEngine::new(
        runtime,
        reader,
        bitcoin_rs_chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        bitcoin_rs_chain::TipReader::new(tip_cell),
        Some(body),
        QueryEngineLive {
            utxo: None,
            chain_transition: Some(chain_transition),
            enabled: IndexCapabilities::ALL,
        },
    );
    let at = engine.transaction_at_prefix(&txid)?;
    assert_eq!(at.prefix.height, 0);
    assert!(at.answer.is_some());
    Ok(())
}

#[test]
fn historical_reset_completing_after_snapshot_stays_valid() -> Result<(), Box<dyn std::error::Error>>
{
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
    let mut tree = BlockTree::new();
    let tip_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    let watermark = watermark_for(&tree, tip_id)?;
    let tip_snapshot = tip_snapshot_for(&tree, tip_id)?;
    let tip_cell = Arc::new(ArcSwapOption::empty());
    tip_cell.store(Some(Arc::new(tip_snapshot)));
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
    let chain_transition = bitcoin_rs_chain::TransitionDomain::new().stable_read();
    let shared_state = Arc::new(ParkMutex::new(HistoricalSnapshot {
        tx_watermark: Some(watermark),
        sh_watermark: Some(watermark),
        tx_floor: 0,
        sh_floor: 0,
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            TxidRow::scan_prefix(&txid),
            vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
            true,
        )],
    }));
    let reset_state = Arc::clone(&shared_state);
    let runtime_clone = Arc::clone(&runtime);
    let body = Arc::new(MovingBody::new(
        vec![(0, block.block_hash(), consensus_bytes(&block))],
        Some(Box::new(move || {
            reset_state.lock().tx_watermark = None;
            reset_state.lock().sh_watermark = None;
            reset_state.lock().tx_watermark = Some(watermark);
            reset_state.lock().sh_watermark = Some(watermark);
            runtime_clone.wake();
        })),
    ));
    let reader: Arc<dyn IndexReader> = Arc::new(ResetReader {
        state: shared_state,
    });
    let engine = DerivedIndexQueryEngine::new(
        runtime,
        reader,
        bitcoin_rs_chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        bitcoin_rs_chain::TipReader::new(tip_cell),
        Some(body),
        QueryEngineLive {
            utxo: None,
            chain_transition: Some(chain_transition),
            enabled: IndexCapabilities::ALL,
        },
    );
    let at = engine.transaction_at_prefix(&txid)?;
    assert_eq!(at.prefix.height, 0);
    assert_eq!(at.prefix.floor, 0);
    assert!(at.answer.is_some());
    Ok(())
}

#[test]
fn historical_reorg_below_anchor_retries() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let txid = genesis.txs[0].txid();
    let main_child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
    let main_grandchild = child_block(&main_child, vec![main_child.txs[0].clone()])?;
    let side_child = {
        let mut tx = genesis.txs[0].clone();
        tx.outputs[0].value = tx.outputs[0].value.saturating_add(Amount::from_sat(1));
        child_block(&genesis, vec![tx])?
    };
    let mut tree = BlockTree::new();
    let _genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    tree.insert_header(main_child.header, NodeStatus::HeaderValid)?;
    let main_tip_id = tree.insert_header(main_grandchild.header, NodeStatus::HeaderValid)?;
    let side_id = tree.insert_header(side_child.header, NodeStatus::HeaderValid)?;
    let main_watermark = watermark_for(&tree, main_tip_id)?;
    let main_tip = tip_snapshot_for(&tree, main_tip_id)?;
    let side_tip = tip_snapshot_for(&tree, side_id)?;
    let tip_cell = Arc::new(ArcSwapOption::empty());
    tip_cell.store(Some(Arc::new(main_tip)));
    let tip_cell_clone = Arc::clone(&tip_cell);
    let on_read: Option<Box<dyn Fn() + Send>> = Some(Box::new(move || {
        tip_cell_clone.store(Some(Arc::new(side_tip.clone())));
    }));
    let body = Arc::new(MovingBody::new(
        vec![
            (1, main_child.block_hash(), consensus_bytes(&main_child)),
            (
                2,
                main_grandchild.block_hash(),
                consensus_bytes(&main_grandchild),
            ),
        ],
        on_read,
    ));
    let chain_transition = bitcoin_rs_chain::TransitionDomain::new().stable_read();
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
    let reader = Arc::new(HistoricalReader {
        snapshot: HistoricalSnapshot {
            tx_watermark: Some(main_watermark),
            sh_watermark: Some(main_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&txid),
                vec![
                    (TxidRow::row(&txid, 1).to_db_row().to_vec(), vec![0]),
                    (TxidRow::row(&txid, 2).to_db_row().to_vec(), vec![0]),
                ],
                true,
            )],
        },
    });
    let engine = DerivedIndexQueryEngine::new(
        runtime,
        reader,
        bitcoin_rs_chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        bitcoin_rs_chain::TipReader::new(tip_cell),
        Some(body),
        QueryEngineLive {
            utxo: None,
            chain_transition: Some(chain_transition),
            enabled: IndexCapabilities::ALL,
        },
    );
    assert!(matches!(
        engine.transaction_at_prefix(&txid),
        Err(HistoricalQueryError::Retry)
    ));
    Ok(())
}

#[test]
fn historical_unknown_watermark_hash_retries() -> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
    let mut tree = BlockTree::new();
    let tip_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    let tip = tip_snapshot_for(&tree, tip_id)?;
    let unknown = IndexWatermark {
        height: 0,
        hash: [0x77; 32],
    };
    let tip_cell = Arc::new(ArcSwapOption::empty());
    tip_cell.store(Some(Arc::new(tip)));
    let chain_transition = bitcoin_rs_chain::TransitionDomain::new().stable_read();
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
    let reader = Arc::new(HistoricalReader {
        snapshot: HistoricalSnapshot {
            tx_watermark: Some(unknown),
            sh_watermark: Some(unknown),
            tx_floor: 0,
            sh_floor: 0,
            scans: Vec::new(),
        },
    });
    let engine = DerivedIndexQueryEngine::new(
        runtime,
        reader,
        bitcoin_rs_chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        bitcoin_rs_chain::TipReader::new(tip_cell),
        None,
        QueryEngineLive {
            utxo: None,
            chain_transition: Some(chain_transition),
            enabled: IndexCapabilities::ALL,
        },
    );
    assert!(matches!(
        engine.transaction_at_prefix(&txid),
        Err(HistoricalQueryError::Retry)
    ));
    Ok(())
}

#[test]
fn historical_stale_watermark_anchors_at_fork_and_excludes_orphans()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let main_child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
    let stale_child = {
        let mut tx = genesis.txs[0].clone();
        tx.outputs[0].value = tx.outputs[0].value.saturating_add(Amount::from_sat(5));
        child_block(&genesis, vec![tx])?
    };
    let stale_txid = stale_child.txs[0].txid();
    let mut tree = BlockTree::new();
    let _genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    let main_id = tree.insert_header(main_child.header, NodeStatus::HeaderValid)?;
    let stale_id = tree.insert_header(stale_child.header, NodeStatus::HeaderValid)?;
    let stale_watermark = watermark_for(&tree, stale_id)?;
    let main_tip = tip_snapshot_for(&tree, main_id)?;
    let tip_cell = Arc::new(ArcSwapOption::empty());
    tip_cell.store(Some(Arc::new(main_tip)));
    let chain_transition = bitcoin_rs_chain::TransitionDomain::new().stable_read();
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
    let stale_prefix = TxidRow::scan_prefix(&stale_txid);
    let reader = Arc::new(HistoricalReader {
        snapshot: HistoricalSnapshot {
            tx_watermark: Some(stale_watermark),
            sh_watermark: Some(stale_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                stale_prefix,
                vec![(TxidRow::row(&stale_txid, 1).to_db_row().to_vec(), vec![0])],
                true,
            )],
        },
    });
    let engine = DerivedIndexQueryEngine::new(
        runtime,
        reader,
        bitcoin_rs_chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        bitcoin_rs_chain::TipReader::new(tip_cell),
        Some(Arc::new(MovingBody::new(
            vec![(1, main_child.block_hash(), consensus_bytes(&main_child))],
            None,
        ))),
        QueryEngineLive {
            utxo: None,
            chain_transition: Some(chain_transition),
            enabled: IndexCapabilities::ALL,
        },
    );
    let at = engine.transaction_at_prefix(&stale_txid)?;
    assert_eq!(at.prefix.height, 0);
    assert_eq!(at.prefix.floor, 0);
    assert_eq!(at.answer, None);
    Ok(())
}

#[test]
fn historical_tx_positive_floor_scopes_absence_and_rejects_anchor_below_floor()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let txid = genesis.txs[0].txid();
    let child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
    let mut tree = BlockTree::new();
    tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    let tip_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
    let tip_watermark = watermark_for(&tree, tip_id)?;
    let (fixture, _) = HistoricalFixture::build(
        tree,
        tip_id,
        HistoricalConfig {
            tx_watermark: Some(tip_watermark),
            sh_watermark: Some(tip_watermark),
            tx_floor: 1,
            sh_floor: 0,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&txid),
                vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
                true,
            )],
            bodies: vec![
                (0, genesis.block_hash(), consensus_bytes(&genesis)),
                (1, child.block_hash(), consensus_bytes(&child)),
            ],
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?;
    let at = fixture.engine.transaction_at_prefix(&txid)?;
    assert_eq!(at.prefix.floor, 1);
    assert_eq!(at.prefix.height, 1);
    assert_eq!(at.answer, None);
    let mut deep_tree = BlockTree::new();
    let deep_genesis_id = deep_tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    let floor_watermark = IndexWatermark {
        height: 0,
        hash: *deep_tree.node(deep_genesis_id)?.hash.as_byte_array(),
    };
    let (floor_fixture, _) = HistoricalFixture::build(
        deep_tree,
        deep_genesis_id,
        HistoricalConfig {
            tx_watermark: Some(floor_watermark),
            sh_watermark: Some(floor_watermark),
            tx_floor: 5,
            sh_floor: 0,
            scans: Vec::new(),
            bodies: Vec::new(),
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?;
    assert!(matches!(
        floor_fixture.engine.transaction_at_prefix(&txid),
        Err(HistoricalQueryError::Unavailable(
            HistoricalUnavailableCause::PrefixBelowFloor { floor: 5 }
        ))
    ));
    Ok(())
}

#[test]
fn historical_full_history_positive_floor_is_unproven() -> Result<(), Box<dyn std::error::Error>> {
    let (block, _, scripthash, _) = block_with_spending_transaction()?;
    let child = child_block(&block, vec![block.txs[0].clone()])?;
    let mut tree = BlockTree::new();
    let _genesis_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    let tip_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
    let watermark = watermark_for(&tree, tip_id)?;
    let (fixture, _) = HistoricalFixture::build(
        tree,
        tip_id,
        HistoricalConfig {
            tx_watermark: Some(watermark),
            sh_watermark: Some(watermark),
            tx_floor: 0,
            sh_floor: 1,
            scans: vec![scan_response(
                ColumnFamily::Funding,
                ScriptHashRow::scan_prefix(scripthash),
                vec![(
                    ScriptHashRow::row(scripthash, 0).to_db_row().to_vec(),
                    vec![0],
                )],
                true,
            )],
            bodies: vec![
                (0, block.block_hash(), consensus_bytes(&block)),
                (1, child.block_hash(), consensus_bytes(&child)),
            ],
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?;
    assert!(matches!(
        fixture.engine.script_history_at_prefix(scripthash),
        Err(HistoricalQueryError::Unavailable(
            HistoricalUnavailableCause::Shared(TxUnavailableCause::HistoryUnproven { floor: 1 })
        ))
    ));
    Ok(())
}

#[test]
fn historical_standalone_spender_scoped_none_above_floor() -> Result<(), Box<dyn std::error::Error>>
{
    let (block, outpoint, _, _) = block_with_spending_transaction()?;
    let child = child_block(&block, vec![block.txs[0].clone()])?;
    let mut tree = BlockTree::new();
    let _genesis_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    let tip_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
    let watermark = watermark_for(&tree, tip_id)?;
    let (fixture, _) = HistoricalFixture::build(
        tree,
        tip_id,
        HistoricalConfig {
            tx_watermark: Some(watermark),
            sh_watermark: Some(watermark),
            tx_floor: 0,
            sh_floor: 1,
            scans: vec![scan_response(
                ColumnFamily::Spending,
                SpendingPrefixRow::scan_prefix(&outpoint),
                vec![(
                    SpendingPrefixRow::row(&outpoint, 0).to_db_row().to_vec(),
                    vec![0],
                )],
                true,
            )],
            bodies: vec![
                (0, block.block_hash(), consensus_bytes(&block)),
                (1, child.block_hash(), consensus_bytes(&child)),
            ],
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?;
    let at = fixture.engine.spender_at_prefix(outpoint)?;
    assert_eq!(at.prefix.floor, 1);
    assert_eq!(at.prefix.height, 1);
    assert_eq!(at.answer, None);
    Ok(())
}

#[test]
fn historical_mixed_cap_script_anchors_at_sh_watermark() -> Result<(), Box<dyn std::error::Error>> {
    let (genesis, chain, scripthash) = paying_chain()?;
    let mut script_tree = BlockTree::new();
    let mut script_tip_id = script_tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    for block in &chain {
        script_tip_id = script_tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    }
    assert_eq!(script_tree.node(script_tip_id)?.height, 2);
    let script_middle_id = script_tree
        .node_at_height_from(script_tip_id, 1)
        .ok_or_else(|| std::io::Error::other("middle present"))?;
    let mut bodies = Vec::new();
    bodies.push((0, genesis.block_hash(), consensus_bytes(&genesis)));
    for (height, block) in [1u32, 2u32].iter().zip(chain.iter()) {
        bodies.push((*height, block.block_hash(), consensus_bytes(block)));
    }
    let funding_scans = vec![scan_response(
        ColumnFamily::Funding,
        ScriptHashRow::scan_prefix(scripthash),
        vec![
            (
                ScriptHashRow::row(scripthash, 0).to_db_row().to_vec(),
                vec![0],
            ),
            (
                ScriptHashRow::row(scripthash, 1).to_db_row().to_vec(),
                vec![0],
            ),
            (
                ScriptHashRow::row(scripthash, 2).to_db_row().to_vec(),
                vec![0],
            ),
        ],
        true,
    )];
    let script_tx_watermark = watermark_for(&script_tree, script_tip_id)?;
    let script_sh_watermark = watermark_for(&script_tree, script_middle_id)?;
    let (script_fixture, _) = HistoricalFixture::build(
        script_tree,
        script_tip_id,
        HistoricalConfig {
            tx_watermark: Some(script_tx_watermark),
            sh_watermark: Some(script_sh_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: funding_scans,
            bodies,
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?;
    let script_at = script_fixture.engine.script_history_at_prefix(scripthash)?;
    assert_eq!(script_at.prefix.height, 1);
    assert_eq!(script_at.prefix.floor, 0);
    for record in &script_at.answer.history {
        assert!(record.height <= 1);
    }
    Ok(())
}

#[test]
fn historical_mixed_cap_tx_anchors_at_tx_watermark() -> Result<(), Box<dyn std::error::Error>> {
    let (genesis, chain, _scripthash) = paying_chain()?;
    let mut tx_tree = BlockTree::new();
    let mut tx_tip_id = tx_tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    for block in &chain {
        tx_tip_id = tx_tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    }
    assert_eq!(tx_tree.node(tx_tip_id)?.height, 2);
    let tx_middle_id = tx_tree
        .node_at_height_from(tx_tip_id, 1)
        .ok_or_else(|| std::io::Error::other("middle present"))?;
    let mut bodies = Vec::new();
    bodies.push((0, genesis.block_hash(), consensus_bytes(&genesis)));
    for (height, block) in [1u32, 2u32].iter().zip(chain.iter()) {
        bodies.push((*height, block.block_hash(), consensus_bytes(block)));
    }
    let funding_txid_height_two = chain[1].txs[0].txid();
    let tx_scans = vec![scan_response(
        ColumnFamily::TxConfirmed,
        TxidRow::scan_prefix(&funding_txid_height_two),
        vec![(
            TxidRow::row(&funding_txid_height_two, 2)
                .to_db_row()
                .to_vec(),
            vec![0],
        )],
        true,
    )];
    let tx_tx_watermark = watermark_for(&tx_tree, tx_tip_id)?;
    let tx_sh_watermark = watermark_for(&tx_tree, tx_middle_id)?;
    let (tx_fixture, _) = HistoricalFixture::build(
        tx_tree,
        tx_tip_id,
        HistoricalConfig {
            tx_watermark: Some(tx_tx_watermark),
            sh_watermark: Some(tx_sh_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: tx_scans,
            bodies,
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?;
    let tx_at = tx_fixture
        .engine
        .transaction_at_prefix(&funding_txid_height_two)?;
    assert_eq!(tx_at.prefix.height, 2);
    assert!(tx_at.answer.is_some());
    assert_eq!(tx_at.answer.as_ref().map(|(h, _)| *h), Some(2));
    Ok(())
}

#[test]
fn historical_duplicate_txid_returns_earliest_verified_and_skips_stale()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let mut target = genesis.txs[0].clone();
    target.outputs[0].value = target.outputs[0].value.saturating_add(Amount::from_sat(7));
    let target_txid = target.txid();
    let main_plain = child_block(&genesis, vec![genesis.txs[0].clone()])?;
    let main_mid = child_block(&main_plain, vec![target.clone()])?;
    let main_tip = child_block(&main_mid, vec![target.clone()])?;
    let stale_child = child_block(&genesis, vec![target.clone(), genesis.txs[0].clone()])?;
    let mut tree = BlockTree::new();
    let _genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    let _plain_id = tree.insert_header(main_plain.header, NodeStatus::HeaderValid)?;
    let _mid_id = tree.insert_header(main_mid.header, NodeStatus::HeaderValid)?;
    let main_tip_id = tree.insert_header(main_tip.header, NodeStatus::HeaderValid)?;
    let _stale_id = tree.insert_header(stale_child.header, NodeStatus::HeaderValid)?;
    let watermark = watermark_for(&tree, main_tip_id)?;
    let (fixture, _) = HistoricalFixture::build(
        tree,
        main_tip_id,
        HistoricalConfig {
            tx_watermark: Some(watermark),
            sh_watermark: Some(watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&target_txid),
                vec![
                    (TxidRow::row(&target_txid, 1).to_db_row().to_vec(), vec![0]),
                    (TxidRow::row(&target_txid, 2).to_db_row().to_vec(), vec![0]),
                    (TxidRow::row(&target_txid, 3).to_db_row().to_vec(), vec![0]),
                ],
                true,
            )],
            bodies: vec![
                (1, main_plain.block_hash(), consensus_bytes(&main_plain)),
                (2, main_mid.block_hash(), consensus_bytes(&main_mid)),
                (3, main_tip.block_hash(), consensus_bytes(&main_tip)),
            ],
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?;
    let at = fixture.engine.transaction_at_prefix(&target_txid)?;
    assert_eq!(at.prefix.height, 3);
    let Some((height, _)) = at.answer else {
        return Err(std::io::Error::other("duplicate must verify").into());
    };
    assert_eq!(height, 2);
    Ok(())
}

#[test]
fn historical_no_covered_prefix_for_reset_claim() -> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
    let mut tree = BlockTree::new();
    let tip_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    let (fixture, _) = HistoricalFixture::build(
        tree,
        tip_id,
        HistoricalConfig {
            tx_watermark: None,
            sh_watermark: None,
            tx_floor: 0,
            sh_floor: 0,
            scans: Vec::new(),
            bodies: Vec::new(),
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?;
    assert!(matches!(
        fixture.engine.transaction_at_prefix(&txid),
        Err(HistoricalQueryError::Unavailable(
            HistoricalUnavailableCause::NoCoveredPrefix { .. }
        ))
    ));
    assert!(matches!(
        fixture
            .engine
            .script_history_at_prefix(ScriptHash::new(&[])),
        Err(HistoricalQueryError::Unavailable(
            HistoricalUnavailableCause::NoCoveredPrefix { .. }
        ))
    ));
    Ok(())
}

#[test]
fn historical_budgets_truncation_and_missing_map_to_shared()
-> Result<(), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
    let mut truncated_tree = BlockTree::new();
    let truncated_tip_id = truncated_tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    let truncated_watermark = watermark_for(&truncated_tree, truncated_tip_id)?;
    let truncated = HistoricalFixture::build(
        truncated_tree,
        truncated_tip_id,
        HistoricalConfig {
            tx_watermark: Some(truncated_watermark),
            sh_watermark: Some(truncated_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&txid),
                vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
                false,
            )],
            bodies: Vec::new(),
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?
    .0;
    assert!(matches!(
        truncated.engine.transaction_at_prefix(&txid),
        Err(HistoricalQueryError::Unavailable(
            HistoricalUnavailableCause::Shared(_)
        ))
    ));
    let mut missing_tree = BlockTree::new();
    let missing_tip_id = missing_tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    let missing_watermark = watermark_for(&missing_tree, missing_tip_id)?;
    let missing = HistoricalFixture::build(
        missing_tree,
        missing_tip_id,
        HistoricalConfig {
            tx_watermark: Some(missing_watermark),
            sh_watermark: Some(missing_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&txid),
                vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), vec![0])],
                true,
            )],
            bodies: Vec::new(),
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?
    .0;
    assert!(matches!(
        missing.engine.transaction_at_prefix(&txid),
        Err(HistoricalQueryError::Unavailable(
            HistoricalUnavailableCause::Shared(TxUnavailableCause::BlockBodyMissing { .. })
        ))
    ));
    Ok(())
}

#[test]
fn historical_budgets_health_and_capability_map_to_shared() -> Result<(), Box<dyn std::error::Error>>
{
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
    let mut failed_tree = BlockTree::new();
    let failed_tip_id = failed_tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    let failed_watermark = watermark_for(&failed_tree, failed_tip_id)?;
    let (failed_fixture, _) = HistoricalFixture::build(
        failed_tree,
        failed_tip_id,
        HistoricalConfig {
            tx_watermark: Some(failed_watermark),
            sh_watermark: Some(failed_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: Vec::new(),
            bodies: Vec::new(),
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?;
    failed_fixture
        .runtime
        .publish_failed("injected worker failure");
    assert!(matches!(
        failed_fixture.engine.transaction_at_prefix(&txid),
        Err(HistoricalQueryError::Unavailable(
            HistoricalUnavailableCause::Shared(_)
        ))
    ));
    let mut disabled_tree = BlockTree::new();
    let disabled_tip_id = disabled_tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    let disabled_watermark = watermark_for(&disabled_tree, disabled_tip_id)?;
    let (disabled_fixture, _) = HistoricalFixture::build(
        disabled_tree,
        disabled_tip_id,
        HistoricalConfig {
            tx_watermark: Some(disabled_watermark),
            sh_watermark: Some(disabled_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: Vec::new(),
            bodies: Vec::new(),
            on_first_read: None,
            enabled: IndexCapabilities::TX_LOOKUP,
        },
    )?;
    assert!(matches!(
        disabled_fixture
            .engine
            .script_history_at_prefix(ScriptHash::new(&[])),
        Err(HistoricalQueryError::Unavailable(
            HistoricalUnavailableCause::Shared(TxUnavailableCause::CapabilityDisabled(_))
        ))
    ));
    let tx_only = disabled_fixture.engine.transaction_at_prefix(&txid)?;
    assert_eq!(tx_only.prefix.height, 0);
    Ok(())
}

#[test]
fn historical_deep_stale_branch_exhausts_shared_ancestry_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    let mut main_tip_id = genesis_id;
    let mut main_tip_block = genesis.clone();
    for _ in 0..320 {
        let child = child_block(&main_tip_block, vec![main_tip_block.txs[0].clone()])?;
        main_tip_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
        main_tip_block = child;
    }
    let mut stale_tip_id = genesis_id;
    let mut stale_tip_block = genesis.clone();
    for _ in 0..320 {
        let mut tx = stale_tip_block.txs[0].clone();
        tx.outputs[0].value = tx.outputs[0].value.saturating_add(Amount::from_sat(1));
        let child = child_block(&stale_tip_block, vec![tx])?;
        stale_tip_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
        stale_tip_block = child;
    }
    let stale_watermark = watermark_for(&tree, stale_tip_id)?;
    let txid = genesis.txs[0].txid();
    let (fixture, _) = HistoricalFixture::build(
        tree,
        main_tip_id,
        HistoricalConfig {
            tx_watermark: Some(stale_watermark),
            sh_watermark: Some(stale_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: Vec::new(),
            bodies: Vec::new(),
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?;
    assert!(matches!(
        fixture.engine.transaction_at_prefix(&txid),
        Err(HistoricalQueryError::Unavailable(
            HistoricalUnavailableCause::AncestryBudgetExhausted { .. }
        ))
    ));
    Ok(())
}
