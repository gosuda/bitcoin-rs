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
    BasicFilter, ConsumerCursorUpdate, IndexCapabilities, IndexReader, IndexWatermark, IndexWriter,
    Indexer, PreparedBatch, PreparedBatchLimits, ScriptHash, SpentCoin, SpentCoins, TxIndexScanRow,
    TxIndexSnapshot,
};
use bitcoin_rs_storage::budget::UnboundedBudget;
use bitcoin_rs_storage::committed_facts::{CommittedBlock, CreatedOutput, SpentPrevout, TxFacts};
use bitcoin_rs_storage::{Bytes, PrefixScanLimit, RocksDbStore};

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
                script: Bytes::new(),
                height,
                coinbase: true,
            }],
            outputs: vec![CreatedOutput {
                vout: 0,
                value: coin.value,
                script: Bytes::from(coin.script.clone()),
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
                    script: Bytes::from(previous_coin.script),
                    height: previous_coin.height,
                    coinbase: previous_coin.coinbase,
                }],
                outputs: vec![CreatedOutput {
                    vout: 0,
                    value: CHILD_VALUE,
                    script: Bytes::from(spend_script),
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
