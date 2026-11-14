use crate::TxIndexSnapshot;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::types::{TxPosition, TxPositionValue, TxidRow};
use crate::{HashPrefixRow, IndexCapabilities, ScriptHashRow, ScriptLiveRow, SpendingPrefixRow};
use arc_swap::ArcSwapOption;
use bitcoin_rs_consensus::primitives::{
    Amount, Block, BlockHash, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid,
    Witness, consensus_bytes,
};
use bitcoin_rs_execution::chain::{NodeStatus, regtest_fixture};
use bitcoin_rs_storage::{ColumnFamily, PrefixScan, PrefixScanLimit};

use super::*;
use crate::{IndexCapability, IndexWatermark, RetryReason};
use bitcoin_rs_execution::chain::TipSnapshot;
use bitcoin_rs_execution::chain::{BlockTree, NodeId};
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

    fn history_scan(&self, scripthash: ScriptHash) -> Result<TxIndexScan, IndexError> {
        let mut scan = self.typed_scan(
            ColumnFamily::Funding,
            &ScriptHashRow::scan_prefix(scripthash),
        )?;
        for row in &mut scan.rows {
            row.row.height = crate::types::encode_height(!u32::from_be_bytes(row.row.height));
        }
        Ok(scan)
    }
}

impl TxIndexSnapshot for QuerySnapshot {
    fn compact_filter(
        &self,
        height: u32,
        hash: &[u8; 32],
    ) -> Result<Option<crate::BasicFilter>, IndexError> {
        let key = crate::segment::format::encode_filter_key(0, height);
        let scan = self.scan_for(ColumnFamily::Filters, &key);
        Ok(scan.rows.iter().find_map(|(_, value)| {
            let (block_hash, filter_hash, header, filter) =
                crate::segment::format::decode_filter_value(value)?;
            (block_hash == *hash).then(|| crate::BasicFilter {
                filter: filter.to_vec(),
                hash: filter_hash,
                header,
            })
        }))
    }

    fn capability_watermark(
        &self,
        _capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        Ok(Some(self.watermark))
    }

    fn tx_lookup_page(
        &self,
        start_after: Option<&[u8]>,
        limit: PrefixScanLimit,
    ) -> Result<crate::TxIndexPage, IndexError> {
        fake_family_page(&self.scans, ColumnFamily::TxConfirmed, start_after, limit)
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
        self.history_scan(scripthash)
    }

    fn funding_rows_from(
        &self,
        scripthash: ScriptHash,
        start_height: u32,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        let mut scan = self.history_scan(scripthash)?;
        scan.rows.retain(|row| row.row.height() <= start_height);
        scan.rows.truncate(limit.max_rows);
        Ok(scan)
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
        let scan = self.scan_for(
            ColumnFamily::ScriptLive,
            &ScriptHashRow::scan_prefix(scripthash),
        );
        let encoded_bytes = scan.rows.iter().fold(0_usize, |total, (key, value)| {
            total.saturating_add(key.len()).saturating_add(value.len())
        });
        let mut rows = Vec::with_capacity(scan.rows.len());
        let mut coins = Vec::with_capacity(scan.rows.len());
        for (key, value) in scan.rows {
            rows.push(
                ScriptLiveRow::from_db_row(&key)
                    .ok_or(IndexError::InvalidPrefixRowLength { len: key.len() })?,
            );
            coins.push(
                crate::types::ScriptLiveCoin::decode_value(&value)
                    .map_err(|_| IndexError::InvalidLiveRowValue { len: value.len() })?,
            );
        }
        Ok(crate::ScriptLiveScan {
            rows,
            coins,
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
    range_reads: AtomicUsize,
}

impl BlockBodySource for SingleBlockBody {
    fn block_body(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
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
        self.range_reads.fetch_add(1, Ordering::Relaxed);
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        self.body.get(start..end).map(<[u8]>::to_vec)
    }
}

impl QueryFixture {
    fn new(config: FixtureConfig) -> Result<Self, crate::portable::TestError> {
        Self::new_with_transition(config, None)
    }

    fn new_with_transition(
        config: FixtureConfig,
        chain_transition: Option<bitcoin_rs_execution::chain::StableRead>,
    ) -> Result<Self, crate::portable::TestError> {
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

        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = DerivedIndexRuntime::new(wake_tx);
        let watermark = config.watermark.unwrap_or(IndexWatermark {
            height: tip.height,
            hash: *tip.hash.as_byte_array(),
        });
        let reader = Arc::new(QueryReader {
            snapshot: QuerySnapshot {
                watermark,
                scans: config.scans,
            },
        });
        let body = if config.retain_body && blocks.len() == 1 {
            Some(Arc::new(SingleBlockBody {
                range_reads: AtomicUsize::new(0),
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
                range_reads: AtomicUsize::new(0),
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
            bitcoin_rs_execution::chain::BlockTreeReader::new(tree),
            bitcoin_rs_execution::chain::TipReader::new(applied_tip),
            body_source,
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition,
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

// SYNC-03, IDX-03
#[test]
fn unusable_worker_makes_queries_unavailable() -> Result<(), crate::portable::TestError> {
    for publish in [true, false] {
        let block = Network::Regtest.genesis_block();
        let txid = block.txs[0].txid();
        let fixture = QueryFixture::new(FixtureConfig {
            block,
            retain_body: true,
            scans: Vec::new(),
            watermark: None,
            extra_blocks: Vec::new(),
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

// SYNC-03
#[test]
fn filter_failure_refuses_filters_but_preserves_durable_progress_and_tx_queries()
-> Result<(), crate::portable::TestError> {
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
    assert!(filters_only.enabled);
    assert_ne!(filters_only.state, CapabilityState::Disabled);
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

fn history_row_raw(
    scripthash: ScriptHash,
    height: u32,
    occurrences: &[crate::types::ScriptHistoryOccurrence],
) -> (Vec<u8>, Vec<u8>) {
    let row = HashPrefixRow {
        prefix: ScriptHashRow::scan_prefix(scripthash),
        height: (!height).to_be_bytes(),
    };
    (
        row.to_db_row().to_vec(),
        crate::types::ScriptHistoryOccurrence::encode_all(occurrences),
    )
}

fn history_row(
    scripthash: ScriptHash,
    height: u32,
    occurrences: &[(Txid, TxPosition, u8)],
) -> (Vec<u8>, Vec<u8>) {
    let encoded: Vec<_> = occurrences
        .iter()
        .map(
            |(txid, position, flags)| crate::types::ScriptHistoryOccurrence {
                scripthash,
                txid: *txid.as_bytes(),
                position: *position,
                flags: *flags,
            },
        )
        .collect();
    history_row_raw(scripthash, height, &encoded)
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

// IDX-03
#[test]
fn transaction_rejects_watermark_from_rival_tip() -> Result<(), crate::portable::TestError> {
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
    })?;

    assert!(matches!(
        fixture.engine.transaction(&txid),
        Err(TxQueryError::Retry(RetryReason::TipMoved { .. }))
    ));
    Ok(())
}

#[test]
fn transaction_rejects_incomplete_prefix_scan() -> Result<(), crate::portable::TestError> {
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
    })?;

    assert!(matches!(
        fixture.engine.transaction(&txid),
        Err(TxQueryError::Unavailable(_))
    ));
    Ok(())
}

#[test]
fn transaction_reports_unavailable_when_indexed_body_is_missing()
-> Result<(), crate::portable::TestError> {
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
    })?;

    assert!(matches!(
        fixture.engine.transaction(&txid),
        Err(TxQueryError::Unavailable(_))
    ));
    Ok(())
}

struct FailingBody {
    error: bitcoin_rs_storage::block_body::BlockBodyReadError,
}

impl BlockBodySource for FailingBody {
    fn block_body(
        &self,
        _height: u32,
        _hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
        Err(self.error.clone())
    }
}

struct MissingBody;

impl BlockBodySource for MissingBody {
    fn block_body(
        &self,
        _height: u32,
        _hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
        Ok(None)
    }
}

fn engine_with_body_source(
    block: &Block,
    scans: Vec<ScanResponse>,
    body_source: Option<Arc<dyn BlockBodySource>>,
) -> Result<DerivedIndexQueryEngine, crate::portable::TestError> {
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
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = DerivedIndexRuntime::new(wake_tx);
    let reader = Arc::new(QueryReader {
        snapshot: QuerySnapshot {
            watermark: IndexWatermark {
                height: tip.height,
                hash: *tip.hash.as_byte_array(),
            },
            scans,
        },
    });
    Ok(DerivedIndexQueryEngine::new(
        runtime,
        reader,
        bitcoin_rs_execution::chain::BlockTreeReader::new(tree),
        bitcoin_rs_execution::chain::TipReader::new(applied_tip),
        body_source,
        QueryEngineLive {
            enabled: IndexCapabilities::ALL,
            generation: Arc::new(Generation::new(1)),
            historical_verified: None,
            chain_transition: None,
        },
    ))
}

fn engine_with_body_error(
    block: &Block,
    scans: Vec<ScanResponse>,
    error: bitcoin_rs_storage::block_body::BlockBodyReadError,
) -> Result<DerivedIndexQueryEngine, crate::portable::TestError> {
    engine_with_body_source(block, scans, Some(Arc::new(FailingBody { error })))
}

#[derive(Default)]
struct RecordingQueryCharge {
    balance: ParkMutex<(u64, u64)>,
}

impl bitcoin_rs_storage::budget::BudgetCharge for RecordingQueryCharge {
    fn reserve_bytes(
        &self,
        _owner: bitcoin_rs_storage::budget::BudgetOwner,
        _bytes: u64,
    ) -> Result<(), bitcoin_rs_storage::budget::BudgetError> {
        Ok(())
    }

    fn allocate_bytes(
        &self,
        _owner: bitcoin_rs_storage::budget::BudgetOwner,
        bytes: u64,
    ) -> Result<(), bitcoin_rs_storage::budget::BudgetError> {
        let mut balance = self.balance.lock();
        balance.0 += bytes;
        balance.1 = balance.1.max(balance.0);
        Ok(())
    }

    fn release_bytes(&self, _owner: bitcoin_rs_storage::budget::BudgetOwner, bytes: u64) {
        let mut balance = self.balance.lock();
        balance.0 = balance.0.saturating_sub(bytes);
    }

    fn available_bytes(&self, _owner: bitcoin_rs_storage::budget::BudgetOwner) -> u64 {
        u64::MAX
    }
}

// BUD-06
#[test]
fn query_view_capture_charges_query_views_and_drop_returns_it()
-> Result<(), crate::portable::TestError> {
    let genesis = bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block();
    let engine = engine_with_body_source(&genesis, Vec::new(), None)?;
    let charge = Arc::new(RecordingQueryCharge::default());
    let engine = engine.with_query_charge(Some(bitcoin_rs_storage::budget::ChargeHandle::new(
        charge.clone(),
        bitcoin_rs_storage::budget::BudgetOwner::QueryViews,
    )));
    let (view, snapshot) = engine
        .capture_view(IndexCapabilities::TX_LOOKUP)
        .map_err(|_| std::io::Error::other("query view capture refused"))?;
    let (held, _) = *charge.balance.lock();
    assert!(held > 0, "capturing a view charges the query views owner");
    drop(snapshot);
    drop(view);
    let (current, _) = *charge.balance.lock();
    assert_eq!(current, 0, "dropping the view returns its charge");
    Ok(())
}

#[test]
fn transaction_reports_unavailable_when_body_source_returns_none()
-> Result<(), crate::portable::TestError> {
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
fn history_snapshot_reports_unavailable_when_a_funding_body_is_missing()
-> Result<(), crate::portable::TestError> {
    use crate::types::ScriptHistoryOccurrence;
    let block = Network::Regtest.genesis_block();
    let tx = &block.txs[0];
    let scripthash = ScriptHash::new(&tx.outputs[0].script_pubkey);
    let body = consensus_bytes(&block);
    let transaction = consensus_bytes(tx);
    let offset = body
        .windows(transaction.len())
        .position(|window| window == transaction)
        .ok_or("the coinbase is present")?;
    let offset = u32::try_from(offset).map_err(|_| "offset fits")?;
    let length = u32::try_from(transaction.len()).map_err(|_| "length fits")?;
    let occurrence = ScriptHistoryOccurrence {
        scripthash,
        txid: *tx.txid().as_bytes(),
        position: TxPosition::new(offset, length),
        flags: ScriptHistoryOccurrence::FUNDING,
    };
    let engine = engine_with_body_source(
        &block,
        vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            vec![history_row_raw(scripthash, 0, &[occurrence])],
            true,
        )],
        Some(Arc::new(MissingBody)),
    )?;

    assert!(matches!(
        engine.history_snapshot(scripthash),
        Err(TxQueryError::Unavailable(
            TxUnavailableCause::BlockBodyMissing { height: 0 }
        ))
    ));
    Ok(())
}

// IDX-03
#[test]
fn transaction_reports_storage_when_body_read_fails() -> Result<(), crate::portable::TestError> {
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
        bitcoin_rs_storage::block_body::BlockBodyReadError::Read("injected read failure".into()),
    )?;

    assert!(matches!(
        engine.transaction(&txid),
        Err(TxQueryError::Storage(_))
    ));
    Ok(())
}

#[test]
fn transaction_reports_storage_when_body_is_corrupt() -> Result<(), crate::portable::TestError> {
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
        bitcoin_rs_storage::block_body::BlockBodyReadError::Corrupt("injected corruption".into()),
    )?;

    assert!(matches!(
        engine.transaction(&txid),
        Err(TxQueryError::Storage(_))
    ));
    Ok(())
}

#[test]
fn empty_position_rows_are_refused_before_body_reads() -> Result<(), crate::portable::TestError> {
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
                vec![history_row(scripthash, 0, &[])],
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
fn spending_position_mismatch_falls_back_to_full_block() -> Result<(), crate::portable::TestError> {
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
fn confirmed_history_serves_stored_occurrences_without_block_bodies()
-> Result<(), crate::portable::TestError> {
    use crate::types::ScriptHistoryOccurrence;
    let (block, outpoint, scripthash, spend_txid) = block_with_spending_transaction()?;
    let funding_txid = block.txs[0].txid();
    let coinbase_at = position_of_transaction(&block, 0)?;
    let spend_at = position_of_transaction(&block, 1)?;
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        scans: vec![
            scan_response(
                ColumnFamily::Funding,
                ScriptHashRow::scan_prefix(scripthash),
                vec![history_row(
                    scripthash,
                    0,
                    &[
                        (funding_txid, coinbase_at, ScriptHistoryOccurrence::FUNDING),
                        (spend_txid, spend_at, ScriptHistoryOccurrence::SPENDING),
                    ],
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
    assert_eq!(
        fixture.full_reads()?,
        0,
        "a stored occurrence names its transaction, so no body is read"
    );
    Ok(())
}

struct MultiBlockBody {
    range_reads: AtomicUsize,
    bodies: Vec<(u32, BlockHash, Vec<u8>)>,
    full_reads: AtomicUsize,
}

impl BlockBodySource for MultiBlockBody {
    fn block_body(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
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
        self.range_reads.fetch_add(1, Ordering::Relaxed);
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        body.get(start..end).map(<[u8]>::to_vec)
    }
}

fn child_block(parent: &Block, txs: Vec<Tx>) -> Result<Block, std::io::Error> {
    let mut block = parent.clone();
    block.header.prev_blockhash = parent.block_hash();
    block.txs = txs;
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| std::io::Error::other("chain test block carries transactions"))?;
    Ok(block)
}

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
fn outpoint_value_returns_confirmed_output_value() -> Result<(), crate::portable::TestError> {
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
    })?;

    assert_eq!(
        fixture.engine.outpoint_value(&OutPoint { txid, vout: 0 })?,
        Some(expected)
    );
    Ok(())
}

#[test]
fn outpoint_value_returns_none_for_out_of_range_vout() -> Result<(), crate::portable::TestError> {
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
    })?;

    assert_eq!(
        fixture.engine.outpoint_value(&OutPoint { txid, vout })?,
        None
    );
    Ok(())
}

#[test]
fn outpoint_value_returns_none_for_unknown_txid() -> Result<(), crate::portable::TestError> {
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
fn funding_prefix_scan_ignores_occurrences_of_other_scripts()
-> Result<(), crate::portable::TestError> {
    use crate::types::ScriptHistoryOccurrence;
    let (block, _, scripthash, _) = block_with_spending_transaction()?;
    let funding_txid = block.txs[0].txid();
    let expected_value = block.txs[0].outputs[0].value.to_sat();
    let coinbase_at = position_of_transaction(&block, 0)?;
    let foreign_at = position_of_transaction(&block, 1)?;
    let mut foreign_bytes = scripthash.to_byte_array();
    foreign_bytes[31] ^= 0xEE;
    let foreign = ScriptHash::from_byte_array(foreign_bytes);
    let mut occurrences = vec![ScriptHistoryOccurrence {
        scripthash,
        txid: *funding_txid.as_bytes(),
        position: coinbase_at,
        flags: ScriptHistoryOccurrence::FUNDING,
    }];
    occurrences.push(ScriptHistoryOccurrence {
        scripthash: foreign,
        txid: *block.txs[1].txid().as_bytes(),
        position: foreign_at,
        flags: ScriptHistoryOccurrence::SPENDING,
    });
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            vec![history_row_raw(scripthash, 0, &occurrences)],
            true,
        )],
        watermark: None,
        extra_blocks: Vec::new(),
    })?;

    let history = fixture.engine.confirmed_history(scripthash)?;
    assert_eq!(
        history.len(),
        1,
        "only the exact script occurrence is served"
    );
    assert_eq!(history[0].txid, funding_txid);
    let snapshot = fixture.engine.history_snapshot(scripthash)?;
    assert_eq!(snapshot.funding.len(), 1);
    assert_eq!(snapshot.funding[0].value, expected_value);
    Ok(())
}

// IDX-02
#[test]
fn history_snapshot_reports_each_confirmed_transaction_once()
-> Result<(), crate::portable::TestError> {
    use crate::types::ScriptHistoryOccurrence;
    let mut block = Network::Regtest.genesis_block();
    let script = block.txs[0].outputs[0].script_pubkey.clone();
    let scripthash = ScriptHash::new(&script);
    let value = block.txs[0].outputs[0].value;
    let coinbase_txid = block.txs[0].txid();
    let duplicate_outputs = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![
            TxOut {
                value,
                script_pubkey: script.clone(),
            },
            TxOut {
                value,
                script_pubkey: script.clone(),
            },
        ],
    };
    let self_spend = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: coinbase_txid,
                vout: 0,
            },
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value,
            script_pubkey: script.clone(),
        }],
    };
    block.txs.push(duplicate_outputs);
    block.txs.push(self_spend);
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| std::io::Error::other("block has transactions"))?;
    let duplicate_txid = block.txs[1].txid();
    let self_spend_txid = block.txs[2].txid();
    let duplicate_at = position_of_transaction(&block, 1)?;
    let self_spend_at = position_of_transaction(&block, 2)?;
    let occurrences = [
        (
            duplicate_txid,
            duplicate_at,
            ScriptHistoryOccurrence::FUNDING,
        ),
        (
            duplicate_txid,
            duplicate_at,
            ScriptHistoryOccurrence::FUNDING,
        ),
        (
            self_spend_txid,
            self_spend_at,
            ScriptHistoryOccurrence::SPENDING,
        ),
        (
            self_spend_txid,
            self_spend_at,
            ScriptHistoryOccurrence::FUNDING,
        ),
    ];
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            vec![history_row(scripthash, 0, &occurrences)],
            true,
        )],
        watermark: None,
        extra_blocks: Vec::new(),
    })?;

    let snapshot = fixture.engine.history_snapshot(scripthash)?;
    let mut history_txids: Vec<_> = snapshot.history.iter().map(|record| record.txid).collect();
    history_txids.sort();
    let mut expected_txids = vec![duplicate_txid, self_spend_txid];
    expected_txids.sort();
    assert_eq!(history_txids, expected_txids);
    assert_eq!(
        snapshot.funding.len(),
        3,
        "funding keeps every distinct output"
    );
    let duplicate_vouts: Vec<u32> = snapshot
        .funding
        .iter()
        .filter(|record| record.txid == duplicate_txid)
        .map(|record| record.vout)
        .collect();
    assert_eq!(duplicate_vouts, [0, 1]);
    assert_eq!(
        snapshot
            .funding
            .iter()
            .filter(|record| record.txid == self_spend_txid)
            .count(),
        1
    );
    Ok(())
}

#[test]
fn history_summary_never_consults_spender_rows() -> Result<(), crate::portable::TestError> {
    use crate::types::ScriptHistoryOccurrence;
    let (block, outpoint, scripthash, _) = block_with_spending_transaction()?;
    let funding_txid = block.txs[0].txid();
    let coinbase_at = position_of_transaction(&block, 0)?;
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        scans: vec![
            scan_response(
                ColumnFamily::Funding,
                ScriptHashRow::scan_prefix(scripthash),
                vec![history_row(
                    scripthash,
                    0,
                    &[(funding_txid, coinbase_at, ScriptHistoryOccurrence::FUNDING)],
                )],
                true,
            ),
            scan_response(
                ColumnFamily::Spending,
                SpendingPrefixRow::scan_prefix(&outpoint),
                Vec::new(),
                false,
            ),
        ],
        watermark: None,
        extra_blocks: Vec::new(),
    })?;

    let snapshot = fixture.engine.history_snapshot(scripthash)?;
    assert_eq!(
        snapshot.history.len(),
        1,
        "the occurrence family owns history"
    );
    assert_eq!(snapshot.funding.len(), 1);
    assert_eq!(snapshot.funding[0].txid, funding_txid);
    assert!(
        matches!(
            fixture.engine.spender(outpoint),
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::PrefixScanTruncated
            ))
        ),
        "the spender family is broken, so the summary cannot have consulted it"
    );
    Ok(())
}

#[test]
fn live_prefix_scan_ignores_coins_paying_other_scripts() -> Result<(), crate::portable::TestError> {
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
    let foreign_scripthash = ScriptHash::new(&foreign_txout.script_pubkey);
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
                    crate::types::ScriptLiveCoin::new(foreign_scripthash, 9, 0, false)
                        .encode_value()?,
                ),
                (
                    ScriptLiveRow::new(scripthash, &real).as_bytes().to_vec(),
                    crate::types::ScriptLiveCoin::new(scripthash, expected_value, 0, true)
                        .encode_value()?,
                ),
            ],
            true,
        )],
        watermark: None,
        extra_blocks: Vec::new(),
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
-> Result<(), crate::portable::TestError> {
    use crate::types::ScriptHistoryOccurrence;
    let (genesis, chain, scripthash) = paying_chain()?;
    let mut funded: Vec<(u32, Txid)> = vec![(0, genesis.txs[0].txid())];
    for tx in &chain[1].txs {
        funded.push((2, tx.txid()));
    }
    for tx in &chain[0].txs {
        funded.push((1, tx.txid()));
    }
    funded.sort();
    let mut rows = Vec::new();
    for (height, txid) in &funded {
        let block = match height {
            0 => &genesis,
            1 => &chain[0],
            _ => &chain[1],
        };
        let index = block
            .txs
            .iter()
            .position(|candidate| candidate.txid() == *txid)
            .ok_or("funded transaction belongs to its block")?;
        rows.push(history_row(
            scripthash,
            *height,
            &[(
                *txid,
                position_of_transaction(block, index)?,
                ScriptHistoryOccurrence::FUNDING,
            )],
        ));
    }
    let fixture = QueryFixture::new(FixtureConfig {
        block: genesis,
        retain_body: true,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            rows,
            true,
        )],
        watermark: None,
        extra_blocks: chain,
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
fn unspent_outputs_orders_live_rows_by_height_then_txid() -> Result<(), crate::portable::TestError>
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
        .map(|(height, outpoint, txout)| -> Result<(Vec<u8>, Vec<u8>), crate::types::ScriptLiveValueError> {
            Ok((
                ScriptLiveRow::new(scripthash, outpoint).as_bytes().to_vec(),
                crate::types::ScriptLiveCoin::new(
                    scripthash,
                    txout.value.to_sat(),
                    *height,
                    false,
                )
                .encode_value()?,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
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
    })?;

    let unspent = fixture.engine.unspent_outputs(scripthash)?;
    assert_eq!(
        fixture
            .engine
            .with_scripthash_limit(0)
            .unspent_outputs(scripthash),
        Err(TxQueryError::Unavailable(
            TxUnavailableCause::ScriptHashLimitExceeded { limit: 0 }
        ))
    );
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
fn confirmed_history_filters_a_shared_prefix_by_exact_script()
-> Result<(), crate::portable::TestError> {
    use crate::types::ScriptHistoryOccurrence;
    let (genesis, chain, scripthash) = paying_chain()?;
    let mut other_bytes = scripthash.to_byte_array();
    other_bytes[31] ^= 0xAA;
    let other = ScriptHash::from_byte_array(other_bytes);
    assert_eq!(
        scripthash.prefix(),
        other.prefix(),
        "the fixture must share the scan prefix"
    );
    let rows = (0..=2_u32)
        .map(|height| {
            history_row(
                scripthash,
                height,
                &[(
                    genesis.txs[0].txid(),
                    TxPosition::new(1 + height, 10),
                    ScriptHistoryOccurrence::FUNDING,
                )],
            )
        })
        .collect::<Vec<_>>();
    let fixture = QueryFixture::new(FixtureConfig {
        block: genesis,
        retain_body: false,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            rows,
            true,
        )],
        watermark: None,
        extra_blocks: chain,
    })?;

    let history = fixture.engine.confirmed_history(other)?;
    assert_eq!(
        history.len(),
        0,
        "another script that shares the prefix is never served"
    );
    Ok(())
}

// IDX-03
#[test]
fn history_limit_counts_occurrences_not_heights() -> Result<(), crate::portable::TestError> {
    use crate::types::ScriptHistoryOccurrence;
    let (genesis, chain, scripthash) = paying_chain()?;
    let txid = genesis.txs[0].txid();
    let occurrences = (0..3_u32)
        .map(|index| {
            (
                txid,
                TxPosition::new(index, 10),
                ScriptHistoryOccurrence::SPENDING,
            )
        })
        .collect::<Vec<_>>();
    let rows = vec![history_row(scripthash, 0, &occurrences)];
    let fixture = QueryFixture::new(FixtureConfig {
        block: genesis,
        retain_body: false,
        scans: vec![scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            rows,
            true,
        )],
        watermark: None,
        extra_blocks: chain,
    })?;

    assert_eq!(
        fixture
            .engine
            .clone()
            .with_scripthash_limit(2)
            .confirmed_history(scripthash),
        Err(TxQueryError::Unavailable(
            TxUnavailableCause::ScriptHashLimitExceeded { limit: 2 }
        )),
        "three occurrences in one height exceed a two-candidate allowance"
    );
    assert_eq!(
        fixture.engine.confirmed_history(scripthash)?.len(),
        1,
        "the same row deduplicates to one transaction record"
    );
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

    fn tx_lookup_page(
        &self,
        start_after: Option<&[u8]>,
        limit: PrefixScanLimit,
    ) -> Result<crate::TxIndexPage, IndexError> {
        fake_family_page(&self.scans, ColumnFamily::TxConfirmed, start_after, limit)
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
        let mut scan = self.typed_scan(
            ColumnFamily::Funding,
            &ScriptHashRow::scan_prefix(scripthash),
        )?;
        for row in &mut scan.rows {
            row.row.height = crate::types::encode_height(!u32::from_be_bytes(row.row.height));
        }
        Ok(scan)
    }

    fn funding_rows_from(
        &self,
        scripthash: ScriptHash,
        start_height: u32,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        let mut scan = self.funding_rows(scripthash, limit)?;
        scan.rows.retain(|row| row.row.height() <= start_height);
        Ok(scan)
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
            coins: Vec::new(),
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

struct SnapshotCountingReader {
    initial: HistoricalSnapshot,
    rewritten: HistoricalSnapshot,
    calls: AtomicUsize,
}

impl IndexReader for SnapshotCountingReader {
    fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(Box::new(self.initial.clone()))
        } else {
            Ok(Box::new(self.rewritten.clone()))
        }
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
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::block_body::BlockBodyReadError> {
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
) -> Result<TipSnapshot, crate::portable::TestError> {
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
) -> Result<IndexWatermark, crate::portable::TestError> {
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
    ) -> Result<(Self, Arc<MovingBody>), crate::portable::TestError> {
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
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let runtime = DerivedIndexRuntime::new(wake_tx);
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
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(&tree)),
            bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&tip_cell)),
            body_source,
            QueryEngineLive {
                enabled,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        );
        let fixture = Self { engine, runtime };
        Ok((fixture, body))
    }
}

#[test]
fn historical_extension_during_read_keeps_same_anchor() -> Result<(), crate::portable::TestError> {
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
    let runtime = DerivedIndexRuntime::new(wake_tx);
    let runtime_clone = Arc::clone(&runtime);
    let on_read: Option<Box<dyn Fn() + Send>> = Some(Box::new(move || {
        tip_cell_clone.store(Some(Arc::new(extension_tip.clone())));
        runtime_clone.wake();
    }));
    let body = Arc::new(MovingBody::new(bodies, on_read));
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
        bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        bitcoin_rs_execution::chain::TipReader::new(tip_cell),
        Some(body),
        QueryEngineLive {
            enabled: IndexCapabilities::ALL,
            generation: Arc::new(Generation::new(1)),
            historical_verified: None,
            chain_transition: None,
        },
    );
    let at = engine.transaction_at_prefix(&txid)?;
    assert_eq!(at.coverage.height, 0);
    assert_eq!(at.coverage.floor, 0);
    assert!(at.value.is_some());
    Ok(())
}

#[test]
fn historical_wake_without_tip_move_stays_valid_for_strict_reads()
-> Result<(), crate::portable::TestError> {
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    let genesis_watermark = watermark_for(&tree, genesis_id)?;
    let tip_snapshot = tip_snapshot_for(&tree, genesis_id)?;
    let tip_cell = Arc::new(ArcSwapOption::empty());
    tip_cell.store(Some(Arc::new(tip_snapshot)));
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = DerivedIndexRuntime::new(wake_tx);
    let runtime_clone = Arc::clone(&runtime);
    let on_read: Option<Box<dyn Fn() + Send>> = Some(Box::new(move || runtime_clone.wake()));
    let body = Arc::new(MovingBody::new(
        vec![(0, block.block_hash(), consensus_bytes(&block))],
        on_read,
    ));
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
        },
    });
    let tree_handle = Arc::new(RwLock::new(tree));
    let historical = DerivedIndexQueryEngine::new(
        Arc::clone(&runtime),
        reader,
        bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::clone(&tree_handle)),
        bitcoin_rs_execution::chain::TipReader::new(Arc::clone(&tip_cell)),
        Some(body),
        QueryEngineLive {
            enabled: IndexCapabilities::ALL,
            generation: Arc::new(Generation::new(1)),
            historical_verified: None,
            chain_transition: None,
        },
    );
    let at = historical.transaction_at_prefix(&txid)?;
    assert_eq!(at.coverage.height, 0);
    assert!(at.value.is_some());
    let runtime_clone = Arc::clone(&runtime);
    let strict_body = Arc::new(MovingBody::new(
        vec![(0, block.block_hash(), consensus_bytes(&block))],
        Some(Box::new(move || runtime_clone.wake())),
    ));
    let strict = DerivedIndexQueryEngine::new(
        runtime,
        strict_reader,
        bitcoin_rs_execution::chain::BlockTreeReader::new(tree_handle),
        bitcoin_rs_execution::chain::TipReader::new(tip_cell),
        Some(strict_body),
        QueryEngineLive {
            enabled: IndexCapabilities::ALL,
            generation: Arc::new(Generation::new(1)),
            historical_verified: None,
            chain_transition: None,
        },
    );
    let at = strict.transaction(&txid)?;
    assert!(at.is_some());
    Ok(())
}

#[test]
fn historical_reorg_above_anchor_stays_valid() -> Result<(), crate::portable::TestError> {
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
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = DerivedIndexRuntime::new(wake_tx);
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
        bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        bitcoin_rs_execution::chain::TipReader::new(tip_cell),
        Some(body),
        QueryEngineLive {
            enabled: IndexCapabilities::ALL,
            generation: Arc::new(Generation::new(1)),
            historical_verified: None,
            chain_transition: None,
        },
    );
    let at = engine.transaction_at_prefix(&txid)?;
    assert_eq!(at.coverage.height, 0);
    assert!(at.value.is_some());
    Ok(())
}

#[test]
fn historical_reset_completing_after_snapshot_stays_valid() -> Result<(), crate::portable::TestError>
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
    let runtime = DerivedIndexRuntime::new(wake_tx);
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
        bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        bitcoin_rs_execution::chain::TipReader::new(tip_cell),
        Some(body),
        QueryEngineLive {
            enabled: IndexCapabilities::ALL,
            generation: Arc::new(Generation::new(1)),
            historical_verified: None,
            chain_transition: None,
        },
    );
    let at = engine.transaction_at_prefix(&txid)?;
    assert_eq!(at.coverage.height, 0);
    assert_eq!(at.coverage.floor, 0);
    assert!(at.value.is_some());
    Ok(())
}

#[test]
fn historical_reorg_below_anchor_stays_valid() -> Result<(), crate::portable::TestError> {
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
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = DerivedIndexRuntime::new(wake_tx);
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
        bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        bitcoin_rs_execution::chain::TipReader::new(tip_cell),
        Some(body),
        QueryEngineLive {
            enabled: IndexCapabilities::ALL,
            generation: Arc::new(Generation::new(1)),
            historical_verified: None,
            chain_transition: None,
        },
    );
    let at = engine.transaction_at_prefix(&txid)?;
    assert!(at.value.is_some());
    assert_eq!(at.coverage.height, 2);
    Ok(())
}

// QRY-01, QRY-02, QRY-03, PRJ-06
#[test]
fn transaction_block_retains_membership_across_reorg_and_aba()
-> Result<(), crate::portable::TestError> {
    for restore in [false, true] {
        let genesis = Network::Regtest.genesis_block();
        let original = child_block(&genesis, vec![genesis.txs[0].clone()])?;
        let mut other_tx = genesis.txs[0].clone();
        other_tx.outputs[0].value = Amount::from_sat(123);
        let replacement = child_block(&genesis, vec![other_tx])?;
        let txid = original.txs[0].txid();
        assert!(original.txs.iter().any(|tx| tx.txid() == txid));
        assert!(replacement.txs.iter().all(|tx| tx.txid() != txid));
        let mut tree = BlockTree::new();
        tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let original_id = tree.insert_header(original.header, NodeStatus::HeaderValid)?;
        let replacement_id = tree.insert_header(replacement.header, NodeStatus::HeaderValid)?;
        let original_tip = tip_snapshot_for(&tree, original_id)?;
        let replacement_tip = tip_snapshot_for(&tree, replacement_id)?;
        let watermark = watermark_for(&tree, original_id)?;
        let tip_cell = Arc::new(ArcSwapOption::empty());
        tip_cell.store(Some(Arc::new(original_tip.clone())));
        let moved = Arc::new(AtomicUsize::new(0));
        let on_read: Option<Box<dyn Fn() + Send>> = {
            let tips = Arc::clone(&tip_cell);
            let moved = Arc::clone(&moved);
            Some(Box::new(move || {
                tips.store(Some(Arc::new(replacement_tip.clone())));
                moved.fetch_add(1, Ordering::SeqCst);
                if restore {
                    tips.store(Some(Arc::new(original_tip.clone())));
                    moved.fetch_add(1, Ordering::SeqCst);
                }
            }))
        };
        let body = Arc::new(MovingBody::new(
            vec![(1, original.block_hash(), consensus_bytes(&original))],
            on_read,
        ));
        let reader = Arc::new(QueryReader {
            snapshot: QuerySnapshot {
                watermark,
                scans: vec![scan_response(
                    ColumnFamily::TxConfirmed,
                    TxidRow::scan_prefix(&txid),
                    vec![(TxidRow::row(&txid, 1).to_db_row().to_vec(), vec![0])],
                    true,
                )],
            },
        });
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let engine = DerivedIndexQueryEngine::new(
            DerivedIndexRuntime::new(wake_tx),
            reader,
            bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
            bitcoin_rs_execution::chain::TipReader::new(tip_cell),
            Some(body),
            QueryEngineLive {
                enabled: IndexCapabilities::ALL,
                generation: Arc::new(Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        );
        let (transaction, identity) = engine
            .transaction_block(&txid)?
            .ok_or_else(|| std::io::Error::other("captured occurrence missing"))?;
        assert_eq!(moved.load(Ordering::SeqCst), if restore { 2 } else { 1 });
        assert_eq!(identity.height, 1);
        assert_eq!(identity.hash, Hash256::from(original.block_hash()));
        assert_eq!(transaction, original.txs[0]);
        assert_ne!(identity.hash, Hash256::from(replacement.block_hash()));
    }
    Ok(())
}

#[test]
fn historical_unknown_watermark_hash_refuses_prefix() -> Result<(), crate::portable::TestError> {
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
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = DerivedIndexRuntime::new(wake_tx);
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
        bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        bitcoin_rs_execution::chain::TipReader::new(tip_cell),
        None,
        QueryEngineLive {
            enabled: IndexCapabilities::ALL,
            generation: Arc::new(Generation::new(1)),
            historical_verified: None,
            chain_transition: None,
        },
    );
    assert!(matches!(
        engine.transaction_at_prefix(&txid),
        Err(TxQueryError::Retry(RetryReason::TipMoved { .. }))
    ));
    Ok(())
}

#[test]
fn historical_stale_watermark_refuses_prefix() -> Result<(), crate::portable::TestError> {
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
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = DerivedIndexRuntime::new(wake_tx);
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
        bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        bitcoin_rs_execution::chain::TipReader::new(tip_cell),
        Some(Arc::new(MovingBody::new(
            vec![(1, main_child.block_hash(), consensus_bytes(&main_child))],
            None,
        ))),
        QueryEngineLive {
            enabled: IndexCapabilities::ALL,
            generation: Arc::new(Generation::new(1)),
            historical_verified: None,
            chain_transition: None,
        },
    );
    assert!(matches!(
        engine.transaction_at_prefix(&stale_txid),
        Err(TxQueryError::Retry(RetryReason::TipMoved { .. }))
    ));
    Ok(())
}

// SYNC-05
#[test]
fn historical_off_chain_watermark_refuses_prefix_reads() -> Result<(), crate::portable::TestError> {
    let genesis = Network::Regtest.genesis_block();
    let main_child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
    let stale_child = {
        let mut tx = genesis.txs[0].clone();
        tx.outputs[0].value = tx.outputs[0].value.saturating_add(Amount::from_sat(5));
        child_block(&genesis, vec![tx])?
    };
    let stale_txid = stale_child.txs[0].txid();
    let script = ScriptHash::from_script_bytes(&[0x51]);
    let mut tree = BlockTree::new();
    let _genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    let main_id = tree.insert_header(main_child.header, NodeStatus::HeaderValid)?;
    let stale_id = tree.insert_header(stale_child.header, NodeStatus::HeaderValid)?;
    let stale_watermark = watermark_for(&tree, stale_id)?;
    let main_tip = tip_snapshot_for(&tree, main_id)?;
    let tip_cell = Arc::new(ArcSwapOption::empty());
    tip_cell.store(Some(Arc::new(main_tip)));
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = DerivedIndexRuntime::new(wake_tx);
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
        bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        bitcoin_rs_execution::chain::TipReader::new(tip_cell),
        Some(Arc::new(MovingBody::new(
            vec![
                (1, main_child.block_hash(), consensus_bytes(&main_child)),
                (1, stale_child.block_hash(), consensus_bytes(&stale_child)),
            ],
            None,
        ))),
        QueryEngineLive {
            enabled: IndexCapabilities::ALL,
            generation: Arc::new(Generation::new(1)),
            historical_verified: None,
            chain_transition: None,
        },
    );
    assert!(matches!(
        engine.transaction_at_prefix(&stale_txid),
        Err(TxQueryError::Retry(RetryReason::TipMoved { .. }))
    ));
    assert!(matches!(
        engine.script_history_at_prefix(script),
        Err(TxQueryError::Retry(RetryReason::TipMoved { .. }))
    ));
    Ok(())
}

// SYNC-01
#[test]
fn assumed_history_view_reports_verified_frontier() -> Result<(), crate::portable::TestError> {
    let genesis = Network::Regtest.genesis_block();
    let child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
    let txid = child.txs[0].txid();
    let mut tree = BlockTree::new();
    tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    let child_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
    let tip = tip_snapshot_for(&tree, child_id)?;
    let tip_cell = Arc::new(ArcSwapOption::empty());
    tip_cell.store(Some(Arc::new(tip)));
    let frontier = Arc::new(RwLock::new(None));
    let reader_frontier = Arc::clone(&frontier);
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = DerivedIndexRuntime::new(wake_tx);
    let watermark = watermark_for(&tree, child_id)?;
    let reader = Arc::new(HistoricalReader {
        snapshot: HistoricalSnapshot {
            tx_watermark: Some(watermark),
            sh_watermark: Some(watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&txid),
                vec![(TxidRow::row(&txid, 1).to_db_row().to_vec(), vec![0])],
                true,
            )],
        },
    });
    let engine = DerivedIndexQueryEngine::new(
        runtime,
        reader,
        bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        bitcoin_rs_execution::chain::TipReader::new(tip_cell),
        Some(Arc::new(MovingBody::new(
            vec![(1, child.block_hash(), consensus_bytes(&child))],
            None,
        ))),
        QueryEngineLive {
            enabled: IndexCapabilities::TX_LOOKUP,
            generation: Arc::new(Generation::new(1)),
            historical_verified: Some(Arc::new(move || Ok(*reader_frontier.read()))),
            chain_transition: None,
        },
    );
    let verified_hash: Hash256 = genesis.block_hash().into();
    *frontier.write() = Some((0, verified_hash));
    let assumed = engine.transaction_at_prefix(&txid)?;
    assert_eq!(
        assumed.verification_state,
        crate::query_api::VerificationState::AssumedHistory {
            verified_height: 0,
            verified_hash,
        }
    );
    *frontier.write() = Some((1, child.block_hash().into()));
    let caught_up = engine.transaction_at_prefix(&txid)?;
    assert_eq!(
        caught_up.verification_state,
        crate::query_api::VerificationState::ChainVerified
    );
    *frontier.write() = None;
    let verified = engine.transaction_at_prefix(&txid)?;
    assert_eq!(
        verified.verification_state,
        crate::query_api::VerificationState::ChainVerified
    );
    Ok(())
}

// IDX-12
#[test]
fn historical_tx_positive_floor_scopes_absence_and_rejects_anchor_below_floor()
-> Result<(), crate::portable::TestError> {
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
            scans: Vec::new(),
            bodies: vec![
                (0, genesis.block_hash(), consensus_bytes(&genesis)),
                (1, child.block_hash(), consensus_bytes(&child)),
            ],
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?;
    let at = fixture.engine.transaction_at_prefix(&txid)?;
    assert_eq!(at.coverage.floor, 1);
    assert_eq!(at.coverage.height, 1);
    assert_eq!(at.value, None);
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
        Err(TxQueryError::Unavailable(
            TxUnavailableCause::OutsideCoverage {
                declared_floor_or_tip: 5
            }
        ))
    ));
    Ok(())
}

#[test]
fn historical_full_history_positive_floor_is_unproven() -> Result<(), crate::portable::TestError> {
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
        Err(TxQueryError::Unavailable(
            TxUnavailableCause::HistoryUnproven { floor: 1 }
        ))
    ));
    Ok(())
}

#[test]
fn historical_standalone_spender_scoped_none_above_floor() -> Result<(), crate::portable::TestError>
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
                    SpendingPrefixRow::row(&outpoint, 1).to_db_row().to_vec(),
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
    assert_eq!(at.coverage.floor, 1);
    assert_eq!(at.coverage.height, 1);
    assert_eq!(at.value, None);
    Ok(())
}

#[test]
fn historical_mixed_cap_script_anchors_at_sh_watermark() -> Result<(), crate::portable::TestError> {
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
    let funding_rows = {
        use crate::types::ScriptHistoryOccurrence;
        let mut rows = Vec::new();
        for (height, block) in
            std::iter::once((0_u32, &genesis)).chain([1_u32, 2_u32].into_iter().zip(chain.iter()))
        {
            for (index, tx) in block.txs.iter().enumerate() {
                if ScriptHash::new(&tx.outputs[0].script_pubkey) != scripthash {
                    continue;
                }
                rows.push(history_row(
                    scripthash,
                    height,
                    &[(
                        tx.txid(),
                        position_of_transaction(block, index)?,
                        ScriptHistoryOccurrence::FUNDING,
                    )],
                ));
            }
        }
        rows
    };
    let funding_scans = vec![scan_response(
        ColumnFamily::Funding,
        ScriptHashRow::scan_prefix(scripthash),
        funding_rows,
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
    assert_eq!(script_at.coverage.height, 1);
    assert_eq!(script_at.coverage.floor, 0);
    for record in &script_at.value.history {
        assert!(record.height <= 1);
    }
    Ok(())
}

#[test]
fn historical_mixed_cap_tx_anchors_at_tx_watermark() -> Result<(), crate::portable::TestError> {
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
    assert_eq!(tx_at.coverage.height, 2);
    assert!(tx_at.value.is_some());
    assert_eq!(tx_at.value.as_ref().map(|(h, _)| *h), Some(2));
    Ok(())
}

#[test]
fn historical_duplicate_txid_returns_earliest_verified_and_skips_stale()
-> Result<(), crate::portable::TestError> {
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
    assert_eq!(at.coverage.height, 3);
    let Some((height, _)) = at.value else {
        return Err(std::io::Error::other("duplicate must verify").into());
    };
    assert_eq!(height, 2);
    Ok(())
}

#[test]
fn historical_no_covered_prefix_for_reset_claim() -> Result<(), crate::portable::TestError> {
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
        Err(TxQueryError::Retry(_))
    ));
    assert!(matches!(
        fixture
            .engine
            .script_history_at_prefix(ScriptHash::new(&[])),
        Err(TxQueryError::Retry(_))
    ));
    Ok(())
}

#[test]
fn historical_budgets_truncation_and_missing_map_to_shared()
-> Result<(), crate::portable::TestError> {
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
        Err(TxQueryError::Unavailable(
            TxUnavailableCause::PrefixScanTruncated
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
        Err(TxQueryError::Unavailable(
            TxUnavailableCause::BlockBodyMissing { .. }
        ))
    ));
    Ok(())
}

#[test]
fn historical_budgets_health_and_capability_map_to_shared() -> Result<(), crate::portable::TestError>
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
        Err(TxQueryError::Unavailable(TxUnavailableCause::WorkerFailed(
            _
        )))
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
        Err(TxQueryError::Unavailable(
            TxUnavailableCause::CapabilityDisabled(_)
        ))
    ));
    let tx_only = disabled_fixture.engine.transaction_at_prefix(&txid)?;
    assert_eq!(tx_only.coverage.height, 0);
    Ok(())
}

#[test]
fn historical_deep_stale_branch_refuses_prefix() -> Result<(), crate::portable::TestError> {
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
        Err(TxQueryError::Retry(RetryReason::TipMoved { .. }))
    ));
    Ok(())
}

// IDX-02, IDX-04
#[test]
fn cursor_page_requires_txlookup_floor_that_covers_the_page()
-> Result<(), crate::portable::TestError> {
    let (genesis, chain, scripthash) = paying_chain()?;
    let mut tree = BlockTree::new();
    let mut tip_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    for block in &chain {
        tip_id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
    }
    let watermark = watermark_for(&tree, tip_id)?;
    let mut funding_rows = Vec::new();
    for (height, block) in
        std::iter::once((0_u32, &genesis)).chain([1_u32, 2_u32].into_iter().zip(chain.iter()))
    {
        for (index, tx) in block.txs.iter().enumerate() {
            funding_rows.push(history_row(
                scripthash,
                height,
                &[(
                    tx.txid(),
                    position_of_transaction(block, index)?,
                    crate::types::ScriptHistoryOccurrence::FUNDING,
                )],
            ));
        }
    }
    funding_rows.reverse();
    let tip_txid = chain[1].txs[0].txid();
    let middle_txids = [chain[0].txs[0].txid(), chain[0].txs[1].txid()];
    let tx_scan = |txid: &Txid, height: u32| {
        scan_response(
            ColumnFamily::TxConfirmed,
            TxidRow::scan_prefix(txid),
            vec![(TxidRow::row(txid, height).to_db_row().to_vec(), vec![0_u8])],
            true,
        )
    };
    let scans = vec![
        scan_response(
            ColumnFamily::Funding,
            ScriptHashRow::scan_prefix(scripthash),
            funding_rows,
            true,
        ),
        tx_scan(&tip_txid, 2),
        tx_scan(&middle_txids[0], 1),
        tx_scan(&middle_txids[1], 1),
    ];
    let (fixture, _) = HistoricalFixture::build(
        tree,
        tip_id,
        HistoricalConfig {
            tx_watermark: Some(watermark),
            sh_watermark: Some(watermark),
            tx_floor: 1,
            sh_floor: 0,
            scans,
            bodies: Vec::new(),
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?;

    let first = fixture.engine.confirmed_history_page(scripthash, None, 3)?;
    assert_eq!(
        first.records.len(),
        3,
        "a first page lists the three newest records without tx lookups"
    );

    let paged = fixture
        .engine
        .confirmed_history_page(scripthash, Some(tip_txid), 3);
    assert!(
        matches!(
            &paged,
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::PrunedPrefixUnproven {
                    family: "transaction index",
                    floor: 1,
                }
            ))
        ),
        "a cursor page must refuse when the tx floor cannot cover it: {paged:?}"
    );

    let genesis_txid = genesis.txs[0].txid();
    let paged = fixture
        .engine
        .confirmed_history_page(scripthash, Some(genesis_txid), 3);
    assert!(
        matches!(
            &paged,
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::PrunedPrefixUnproven { .. }
            ))
        ),
        "a cursor below the tx floor must refuse instead of restarting: {paged:?}"
    );
    Ok(())
}

// QRY-03
#[test]
fn history_query_survives_chain_extension() -> Result<(), crate::portable::TestError> {
    let genesis = Network::Regtest.genesis_block();
    let txid = genesis.txs[0].txid();
    let main_child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
    let side_child = {
        let mut tx = genesis.txs[0].clone();
        tx.outputs[0].value = tx.outputs[0].value.saturating_add(Amount::from_sat(1));
        child_block(&genesis, vec![tx])?
    };
    let mut tree = BlockTree::new();
    let _genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    let main_id = tree.insert_header(main_child.header, NodeStatus::HeaderValid)?;
    let side_id = tree.insert_header(side_child.header, NodeStatus::HeaderValid)?;
    let main_watermark = watermark_for(&tree, main_id)?;
    let main_tip = tip_snapshot_for(&tree, main_id)?;
    let side_tip = tip_snapshot_for(&tree, side_id)?;

    let tip_cell = Arc::new(ArcSwapOption::empty());
    tip_cell.store(Some(Arc::new(main_tip)));

    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = DerivedIndexRuntime::new(wake_tx);
    let tip_cell_clone = Arc::clone(&tip_cell);
    let on_read: Option<Box<dyn Fn() + Send>> = Some(Box::new(move || {
        tip_cell_clone.store(Some(Arc::new(side_tip.clone())));
    }));

    let body = Arc::new(MovingBody::new(
        vec![(1, main_child.block_hash(), consensus_bytes(&main_child))],
        on_read,
    ));

    let reader: Arc<dyn IndexReader> = Arc::new(HistoricalReader {
        snapshot: HistoricalSnapshot {
            tx_watermark: Some(main_watermark),
            sh_watermark: Some(main_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&txid),
                vec![(TxidRow::row(&txid, 1).to_db_row().to_vec(), vec![0])],
                true,
            )],
        },
    });

    let engine = DerivedIndexQueryEngine::new(
        runtime,
        reader,
        bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        bitcoin_rs_execution::chain::TipReader::new(tip_cell),
        Some(body),
        QueryEngineLive {
            enabled: IndexCapabilities::ALL,
            generation: Arc::new(Generation::new(1)),
            historical_verified: None,
            chain_transition: None,
        },
    );

    let at = engine.transaction_at_prefix(&txid)?;
    assert_eq!(at.height, 1);
    assert_eq!(at.coverage.height, 1);
    assert!(at.value.is_some());
    Ok(())
}

// QRY-01
#[test]
fn answer_reads_the_captured_snapshot_when_tail_rows_are_rewritten()
-> Result<(), crate::portable::TestError> {
    let genesis = Network::Regtest.genesis_block();
    let mut tx_a = genesis.txs[0].clone();
    tx_a.outputs.push(TxOut {
        value: Amount::from_sat(1),
        script_pubkey: genesis.txs[0].outputs[0].script_pubkey.clone(),
    });
    let child = child_block(&genesis, vec![tx_a.clone()])?;
    let mut tree = BlockTree::new();
    let _genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    let child_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
    let tip_watermark = watermark_for(&tree, child_id)?;
    let tip = tip_snapshot_for(&tree, child_id)?;
    let txid_a = tx_a.txid();

    let initial = HistoricalSnapshot {
        tx_watermark: Some(tip_watermark),
        sh_watermark: Some(tip_watermark),
        tx_floor: 0,
        sh_floor: 0,
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            TxidRow::scan_prefix(&txid_a),
            vec![(TxidRow::row(&txid_a, 1).to_db_row().to_vec(), vec![0_u8])],
            true,
        )],
    };
    let rewritten = HistoricalSnapshot {
        tx_watermark: Some(tip_watermark),
        sh_watermark: Some(tip_watermark),
        tx_floor: 0,
        sh_floor: 0,
        scans: Vec::new(),
    };

    let tip_cell = Arc::new(ArcSwapOption::empty());
    tip_cell.store(Some(Arc::new(tip)));
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = DerivedIndexRuntime::new(wake_tx);
    let body = Arc::new(MovingBody::new(
        vec![(1, child.block_hash(), consensus_bytes(&child))],
        None,
    ));

    let engine = DerivedIndexQueryEngine::new(
        runtime,
        Arc::new(SnapshotCountingReader {
            initial,
            rewritten,
            calls: AtomicUsize::new(0),
        }),
        bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        bitcoin_rs_execution::chain::TipReader::new(tip_cell),
        Some(body),
        QueryEngineLive {
            enabled: IndexCapabilities::ALL,
            generation: Arc::new(Generation::new(1)),
            historical_verified: None,
            chain_transition: None,
        },
    );

    let at = engine.transaction_at_prefix(&txid_a)?;
    assert!(
        at.value.is_some(),
        "the answer must come from the capture-time snapshot even though the read rewrote the tail rows, got value {:?}",
        at.value
    );
    assert_eq!(at.height, 1);
    assert_eq!(at.coverage.height, 1);
    Ok(())
}

// QRY-05
#[test]
fn below_floor_point_lookups_refuse_with_outside_coverage() -> Result<(), crate::portable::TestError>
{
    let genesis = Network::Regtest.genesis_block();
    let child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
    let mut tree = BlockTree::new();
    let _genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    let child_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
    let tip_watermark = watermark_for(&tree, child_id)?;
    let genesis_txid = genesis.txs[0].txid();
    let outpoint = OutPoint::new(genesis_txid, 0);

    let (fixture, _) = HistoricalFixture::build(
        tree,
        child_id,
        HistoricalConfig {
            tx_watermark: Some(tip_watermark),
            sh_watermark: Some(tip_watermark),
            tx_floor: 1,
            sh_floor: 1,
            scans: vec![
                scan_response(
                    ColumnFamily::TxConfirmed,
                    TxidRow::scan_prefix(&genesis_txid),
                    vec![(
                        TxidRow::row(&genesis_txid, 0).to_db_row().to_vec(),
                        vec![0_u8],
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
            bodies: Vec::new(),
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?;

    let located = fixture.engine.transaction_at_prefix(&genesis_txid);
    assert!(
        matches!(
            &located,
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::OutsideCoverage {
                    declared_floor_or_tip: 1,
                }
            ))
        ),
        "a below-floor txid must refuse instead of returning scoped absence: {located:?}"
    );

    let spent = fixture.engine.spender_at_prefix(outpoint);
    assert!(
        matches!(
            &spent,
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::OutsideCoverage {
                    declared_floor_or_tip: 1,
                }
            ))
        ),
        "a below-floor spender must refuse instead of returning scoped absence: {spent:?}"
    );
    Ok(())
}

// QRY-05
#[test]
fn outside_coverage_is_unavailable() -> Result<(), crate::portable::TestError> {
    let genesis = Network::Regtest.genesis_block();
    let child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    let child_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
    let genesis_watermark = watermark_for(&tree, genesis_id)?;

    let (fixture, _) = HistoricalFixture::build(
        tree,
        child_id,
        HistoricalConfig {
            tx_watermark: Some(genesis_watermark),
            sh_watermark: Some(genesis_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: Vec::new(),
            bodies: vec![
                (0, genesis.block_hash(), consensus_bytes(&genesis)),
                (1, child.block_hash(), consensus_bytes(&child)),
            ],
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?;

    let unknown_txid = Txid(Hash256::from_le_bytes(&[0xEE; 32]));
    let result = fixture.engine.transaction_at_prefix(&unknown_txid);
    assert!(
        matches!(
            result,
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::OutsideCoverage {
                    declared_floor_or_tip: 0
                }
            ))
        ),
        "query outside declared coverage must return OutsideCoverage error, got {result:?}"
    );
    Ok(())
}

// QRY-03
#[test]
fn tip_promising_script_pages_refuse_while_watermark_lags_the_tip()
-> Result<(), crate::portable::TestError> {
    let genesis = Network::Regtest.genesis_block();
    let child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    let child_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
    let genesis_watermark = watermark_for(&tree, genesis_id)?;
    let scripthash = ScriptHash::new(&genesis.txs[0].outputs[0].script_pubkey);
    let funding = history_row(
        scripthash,
        0,
        &[(
            genesis.txs[0].txid(),
            position_of_transaction(&genesis, 0)?,
            crate::types::ScriptHistoryOccurrence::FUNDING,
        )],
    );

    let (fixture, _) = HistoricalFixture::build(
        tree,
        child_id,
        HistoricalConfig {
            tx_watermark: Some(genesis_watermark),
            sh_watermark: Some(genesis_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: vec![scan_response(
                ColumnFamily::Funding,
                ScriptHashRow::scan_prefix(scripthash),
                vec![funding],
                true,
            )],
            bodies: vec![(0, genesis.block_hash(), consensus_bytes(&genesis))],
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?;

    let page = fixture.engine.confirmed_history_page(scripthash, None, 10);
    assert!(
        matches!(&page, Err(TxQueryError::Retry(_))),
        "a tip-promising history page must refuse while the watermark lags the tip: {page:?}"
    );

    let live = fixture.engine.unspent_outputs(scripthash);
    assert!(
        matches!(&live, Err(TxQueryError::Retry(_))),
        "a tip-promising utxo listing must refuse while the watermark lags the tip: {live:?}"
    );

    let embed = fixture.engine.script_history_at_answer(scripthash)?;
    assert_eq!(embed.coverage.height, 0);
    assert_eq!(embed.value.history.len(), 1);
    Ok(())
}

// QRY-03
#[test]
fn tx_lookups_refuse_with_retry_while_watermark_lags_the_tip()
-> Result<(), crate::portable::TestError> {
    let genesis = Network::Regtest.genesis_block();
    let child = child_block(&genesis, vec![genesis.txs[0].clone()])?;
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    let child_id = tree.insert_header(child.header, NodeStatus::HeaderValid)?;
    let genesis_watermark = watermark_for(&tree, genesis_id)?;
    let genesis_txid = genesis.txs[0].txid();
    let outpoint = OutPoint::new(genesis_txid, 0);

    let (fixture, _) = HistoricalFixture::build(
        tree,
        child_id,
        HistoricalConfig {
            tx_watermark: Some(genesis_watermark),
            sh_watermark: Some(genesis_watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: vec![scan_response(
                ColumnFamily::TxConfirmed,
                TxidRow::scan_prefix(&genesis_txid),
                vec![(
                    TxidRow::row(&genesis_txid, 0).to_db_row().to_vec(),
                    vec![0_u8],
                )],
                true,
            )],
            bodies: vec![(0, genesis.block_hash(), consensus_bytes(&genesis))],
            on_first_read: None,
            enabled: IndexCapabilities::ALL,
        },
    )?;

    let found = fixture.engine.transaction(&genesis_txid);
    assert!(
        matches!(&found, Err(TxQueryError::Retry(_))),
        "a current-tip tx lookup must refuse with Retry while the watermark lags: {found:?}"
    );
    let height = fixture.engine.transaction_block(&genesis_txid);
    assert!(
        matches!(&height, Err(TxQueryError::Retry(_))),
        "a current-tip height lookup must refuse with Retry while the watermark lags: {height:?}"
    );
    let value = fixture.engine.outpoint_value(&outpoint);
    assert!(
        matches!(&value, Err(TxQueryError::Retry(_))),
        "a current-tip outpoint lookup must refuse with Retry while the watermark lags: {value:?}"
    );
    Ok(())
}

// QRY-07
#[test]
fn expired_revoked_and_replaced_views_fail_closed() -> Result<(), crate::portable::TestError> {
    let genesis = Network::Regtest.genesis_block();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    let tip = tip_snapshot_for(&tree, genesis_id)?;
    let watermark = watermark_for(&tree, genesis_id)?;
    let generation = Arc::new(Generation::new(1));

    let tip_cell = Arc::new(ArcSwapOption::empty());
    tip_cell.store(Some(Arc::new(tip)));
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let runtime = DerivedIndexRuntime::new(wake_tx);
    let reader: Arc<dyn IndexReader> = Arc::new(ResetReader {
        state: Arc::new(ParkMutex::new(HistoricalSnapshot {
            tx_watermark: Some(watermark),
            sh_watermark: Some(watermark),
            tx_floor: 0,
            sh_floor: 0,
            scans: Vec::new(),
        })),
    });
    let engine = DerivedIndexQueryEngine::new(
        runtime,
        reader,
        bitcoin_rs_execution::chain::BlockTreeReader::new(Arc::new(RwLock::new(tree))),
        bitcoin_rs_execution::chain::TipReader::new(tip_cell),
        None,
        QueryEngineLive {
            enabled: IndexCapabilities::ALL,
            generation: Arc::clone(&generation),
            historical_verified: None,
            chain_transition: None,
        },
    );

    let (view, snapshot) = engine.capture_view(IndexCapabilities::TX_LOOKUP)?;
    let expired_view = view;
    expired_view.expire_for_test();
    let expired = engine.with_view(
        IndexCapabilities::TX_LOOKUP,
        &expired_view,
        snapshot.as_ref(),
        |_, _, _| Ok::<(), TxQueryError>(()),
    );
    assert!(
        matches!(expired, Err(TxQueryError::ExpiredView)),
        "a view past its deadline must fail closed: {expired:?}"
    );

    let (view, snapshot) = engine.capture_view(IndexCapabilities::TX_LOOKUP)?;
    let expired_during_read = engine.with_view(
        IndexCapabilities::TX_LOOKUP,
        &view,
        snapshot.as_ref(),
        |_, view, _| {
            view.expire_for_test();
            Ok::<(), TxQueryError>(())
        },
    );
    assert!(
        matches!(expired_during_read, Err(TxQueryError::ExpiredView)),
        "a view that expires during a read must not return success: {expired_during_read:?}"
    );

    let (view, snapshot) = engine.capture_view(IndexCapabilities::TX_LOOKUP)?;
    let mut moved = engine.clone();
    moved.set_generation_for_test(Arc::new(Generation::new(2)));
    let replaced = moved.with_view(
        IndexCapabilities::TX_LOOKUP,
        &view,
        snapshot.as_ref(),
        |_, _, _| Ok::<(), TxQueryError>(()),
    );
    assert!(
        matches!(replaced, Err(TxQueryError::ExpiredView)),
        "a view from a replaced generation must fail closed: {replaced:?}"
    );

    let (view, snapshot) = engine.capture_view(IndexCapabilities::TX_LOOKUP)?;
    generation.revoke();
    let revoked = engine.with_view(
        IndexCapabilities::TX_LOOKUP,
        &view,
        snapshot.as_ref(),
        |_, _, _| Ok::<(), TxQueryError>(()),
    );
    assert!(
        matches!(revoked, Err(TxQueryError::ExpiredView)),
        "a view whose generation was revoked must fail closed: {revoked:?}"
    );

    let refused = engine.transaction(&genesis.txs[0].txid());
    assert!(
        matches!(refused, Err(TxQueryError::ExpiredView)),
        "a fresh capture on a revoked generation must refuse: {refused:?}"
    );
    Ok(())
}

// QRY-07
#[test]
fn filter_stream_stops_after_callback_revokes_view() -> Result<(), crate::portable::TestError> {
    use crate::CompactFilterQuery;

    let genesis = Network::Regtest.genesis_block();
    let child = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)
        .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
    let stop = Hash256::from(child.block_hash());
    let scans = [(0_u32, &genesis), (1_u32, &child)]
        .into_iter()
        .map(|(height, block)| {
            let key = crate::segment::format::encode_filter_key(0, height);
            scan_response(
                ColumnFamily::Filters,
                key,
                vec![(
                    key.to_vec(),
                    crate::segment::format::encode_filter_value(
                        block.block_hash().as_bytes(),
                        &[0; 32],
                        &[0; 32],
                        &[0],
                    ),
                )],
                true,
            )
        })
        .collect();
    let mut fixture = QueryFixture::new(FixtureConfig {
        block: genesis,
        retain_body: false,
        scans,
        watermark: None,
        extra_blocks: vec![child],
    })?;
    let generation = Arc::new(Generation::new(1));
    fixture
        .engine
        .set_generation_for_test(Arc::clone(&generation));
    let mut emitted = 0;
    let result = fixture.engine.for_each_filter(0, stop, 1, &mut |_, _| {
        emitted += 1;
        generation.revoke();
        true
    });
    assert_eq!(
        emitted, 1,
        "the next filter must not be emitted after expiry"
    );
    assert!(matches!(result, Err(TxQueryError::ExpiredView)));
    Ok(())
}

// PRJ-11
#[test]
fn script_live_takes_no_transition_lock() -> Result<(), crate::portable::TestError> {
    let block = Network::Regtest.genesis_block();
    let script = ScriptHash::from_byte_array([1; 32]);
    let outpoint = OutPoint::new(block.txs[0].txid(), 0);
    let row = ScriptLiveRow::new(script, &outpoint);
    let coin = crate::types::ScriptLiveCoin::new(script, 50_000, 0, true);

    let transition = bitcoin_rs_execution::chain::TransitionDomain::new();
    let stable_read = transition.stable_read();

    let fixture = QueryFixture::new_with_transition(
        FixtureConfig {
            block: block.clone(),
            retain_body: true,
            scans: vec![scan_response(
                ColumnFamily::ScriptLive,
                ScriptHashRow::scan_prefix(script),
                vec![(row.as_bytes().to_vec(), coin.encode_value()?)],
                true,
            )],
            watermark: Some(IndexWatermark {
                height: 0,
                hash: *block.block_hash().as_bytes(),
            }),
            extra_blocks: Vec::new(),
        },
        Some(stable_read.clone()),
    )?;
    let authority = transition.authority();
    let _guard = authority.lock();

    for _ in 0..100 {
        let live = fixture.engine.unspent_outputs(script)?;
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].value, 50_000);
    }

    assert_eq!(
        stable_read.lock_acquisitions(),
        0,
        "ScriptLive must take zero transition locks"
    );
    Ok(())
}

// QRY-02
#[test]
fn traversal_of_a_captured_view_ignores_commits_and_seal_during_it()
-> Result<(), crate::portable::TestError> {
    struct NoSpends;

    impl crate::SpentCoins for NoSpends {
        fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<crate::SpentCoin<'_>> {
            None
        }
    }

    fn commit_one(
        writer: &mut crate::IndexWriter<bitcoin_rs_storage::RocksDbStore>,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<(), crate::portable::TestError> {
        let prepared = writer.prepare_block_with_spent_scripts(
            IndexCapabilities::TX_LOOKUP,
            height,
            hash,
            body,
            &NoSpends,
        )?;
        let mut batch = crate::PreparedBatch::new(crate::PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        if batch.try_push(prepared).is_err() {
            return Err("one block is admitted per batch".into());
        }
        writer.commit_forward(batch)?;
        Ok(())
    }

    fn sealed_generation_count(
        store: &bitcoin_rs_storage::RocksDbStore,
    ) -> Result<usize, crate::portable::TestError> {
        use bitcoin_rs_storage::KvStore as _;
        let snapshot = store.snapshot()?;
        Ok(crate::segment::sealed_generations(snapshot.as_ref(), IndexCapability::TxLookup)?.len())
    }

    let genesis = Network::Regtest.genesis_block();
    let txid_a = genesis
        .txs
        .first()
        .ok_or("genesis carries a coinbase")?
        .txid();
    let dir = tempfile::TempDir::new()?;
    let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open(dir.path())?);
    let scratch = tempfile::TempDir::new()?;
    let mut writer = crate::IndexWriter::open(Arc::clone(&store), 1)?
        .with_seal_scratch(scratch.path().to_path_buf());
    commit_one(
        &mut writer,
        0,
        *genesis.block_hash().as_bytes(),
        &consensus_bytes(&genesis),
    )?;
    assert_eq!(
        sealed_generation_count(&store)?,
        0,
        "no sealed generation exists before the tail reaches its bound"
    );

    let last_height = crate::segment::format::TAIL_MAX_BLOCKS + 1;
    let mut chain = Vec::new();
    let mut parent = genesis.block_hash();
    for height in 1..=last_height {
        let block = regtest_fixture::mined_regtest_child_at(parent, height)
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
        parent = block.block_hash();
        chain.push((
            height,
            *block.block_hash().as_bytes(),
            consensus_bytes(&block),
            block
                .txs
                .first()
                .ok_or("each mined block carries a coinbase")?
                .txid(),
        ));
    }
    let txid_b = chain.first().ok_or("the chain is non-empty")?.3;
    let txid_last = chain.last().ok_or("the chain is non-empty")?.3;
    assert_ne!(
        txid_a, txid_b,
        "each block contributes its own coinbase row"
    );

    let mut tree = BlockTree::new();
    let tip_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
    let tip = tip_snapshot_for(&tree, tip_id)?;
    let tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    applied_tip.store(Some(Arc::new(tip)));
    let reader: Arc<dyn IndexReader> = Arc::new(crate::Indexer::new(Arc::clone(&store)));
    let fresh_reader = Arc::clone(&reader);
    let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
    let engine = DerivedIndexQueryEngine::new(
        DerivedIndexRuntime::new(wake_tx),
        reader,
        bitcoin_rs_execution::chain::BlockTreeReader::new(tree),
        bitcoin_rs_execution::chain::TipReader::new(applied_tip),
        None,
        QueryEngineLive {
            enabled: IndexCapabilities::ALL,
            generation: Arc::new(Generation::new(1)),
            historical_verified: None,
            chain_transition: None,
        },
    );
    let limit = PrefixScanLimit {
        max_rows: 16,
        max_bytes: 4096,
    };
    let values = |scan: &TxIndexScan| {
        scan.rows
            .iter()
            .map(|row| row.value.clone())
            .collect::<Vec<_>>()
    };

    let (view, snapshot) = engine.capture_view(IndexCapabilities::TX_LOOKUP)?;
    let read = |txid: &Txid| {
        engine.with_view(
            IndexCapabilities::TX_LOOKUP,
            &view,
            snapshot.as_ref(),
            |snap: &dyn TxIndexSnapshot, _view, _budget| {
                snap.transaction_rows(txid, limit)
                    .map_err(|error| TxQueryError::Storage(error.to_string().into()))
            },
        )
    };
    let before = values(&read(&txid_a)?);
    assert_eq!(
        before.len(),
        1,
        "the captured view holds the genesis coinbase row"
    );

    let (first_committed_tx, first_committed_rx) = std::sync::mpsc::channel::<()>();
    let (traversed_tx, traversed_rx) = std::sync::mpsc::channel::<()>();
    let worker = std::thread::spawn(move || -> Result<(), crate::portable::TestError> {
        let mut blocks = chain.into_iter();
        let (height, hash, body, _) = blocks.next().ok_or("the chain is non-empty")?;
        commit_one(&mut writer, height, hash, &body)?;
        first_committed_tx
            .send(())
            .map_err(|_| "the reader stopped")?;
        traversed_rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .map_err(|_| "the reader did not traverse the first commit")?;
        for (height, hash, body, _) in blocks {
            commit_one(&mut writer, height, hash, &body)?;
        }
        Ok(())
    });

    first_committed_rx
        .recv_timeout(std::time::Duration::from_secs(120))
        .map_err(|_| "the commit worker did not commit the first block")?;
    assert_eq!(
        values(&read(&txid_a)?),
        before,
        "a traversal that overlaps the first commit must return the capture-time answer"
    );
    assert!(
        read(&txid_b)?.rows.is_empty(),
        "a block committed after capture must not appear in the captured view"
    );
    traversed_tx
        .send(())
        .map_err(|_| "the commit worker stopped")?;

    while !worker.is_finished() {
        assert_eq!(
            values(&read(&txid_a)?),
            before,
            "a traversal overlapping commits must return the capture-time answer"
        );
        assert!(
            read(&txid_b)?.rows.is_empty(),
            "rows committed after capture must not appear in the captured view"
        );
    }
    worker.join().map_err(|_| "commit worker panicked")??;

    assert_eq!(
        sealed_generation_count(&store)?,
        1,
        "committing past the tail bound must seal exactly one generation"
    );
    assert_eq!(
        values(&read(&txid_a)?),
        before,
        "the captured view keeps its answer after the tail seals"
    );
    let fresh = fresh_reader.snapshot()?;
    assert_eq!(
        fresh
            .capability_watermark(IndexCapability::TxLookup)?
            .map(|watermark| watermark.height),
        Some(last_height),
        "the writer committed every block"
    );
    assert_eq!(
        fresh.transaction_rows(&txid_last, limit)?.rows.len(),
        1,
        "a view captured after the commits sees the last block"
    );
    Ok(())
}
// BUD-02
#[test]
fn view_charge_refusal_reports_node_budget() -> Result<(), crate::portable::TestError> {
    let genesis = Network::Regtest.genesis_block();
    let engine = engine_with_body_source(&genesis, Vec::new(), None)?;
    struct Refusing;
    impl bitcoin_rs_storage::budget::BudgetCharge for Refusing {
        fn reserve_bytes(
            &self,
            _owner: bitcoin_rs_storage::budget::BudgetOwner,
            _bytes: u64,
        ) -> Result<(), bitcoin_rs_storage::budget::BudgetError> {
            Err(bitcoin_rs_storage::budget::BudgetError::BudgetExhausted)
        }
        fn allocate_bytes(
            &self,
            _owner: bitcoin_rs_storage::budget::BudgetOwner,
            _bytes: u64,
        ) -> Result<(), bitcoin_rs_storage::budget::BudgetError> {
            Err(bitcoin_rs_storage::budget::BudgetError::BudgetExhausted)
        }
        fn release_bytes(&self, _owner: bitcoin_rs_storage::budget::BudgetOwner, _bytes: u64) {}
        fn available_bytes(&self, _owner: bitcoin_rs_storage::budget::BudgetOwner) -> u64 {
            0
        }
    }
    let engine = engine.with_query_charge(Some(bitcoin_rs_storage::budget::ChargeHandle::new(
        std::sync::Arc::new(Refusing),
        bitcoin_rs_storage::budget::BudgetOwner::QueryViews,
    )));
    assert!(matches!(
        engine.capture_view(IndexCapabilities::TX_LOOKUP),
        Err(TxQueryError::Unavailable(
            TxUnavailableCause::NodeBudgetExhausted
        ))
    ));
    Ok(())
}
