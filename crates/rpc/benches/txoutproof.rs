//! `gettxoutproof` refactor-set benchmark.
//!
//! Both arms of the set run over one identical fixture in one process, so the
//! before/after ratio comes from a single run and cannot be confounded by the
//! rebuild and baseline drift recorded in
//! `docs/solutions/best-practices/criterion-bench-trust-rebuild-drift-baselines-allocator.md`.
//!
//! `before_scan` is the pre-index path: no `tx_index` on the `Context`, so the
//! handler walks every block record, loads each body, deserializes it and hashes
//! every transaction in it. `after_index` is the same call on the same fixture
//! with a populated txindex attached.
//!
//! Block bodies are served from a **real `FlatFileBlockStore`**, the same path
//! production takes: open, `fstat`, seek, read. Serving them from an in-memory
//! map would leave the syscall sequence out entirely, which is the mistake
//! `crates/index/benches/history_resolve.rs` records having made.
//!
//! **These are small-window measurements.** The fixtures are thousands of blocks;
//! mainnet is near a million. The scan arm is linear in the number of records,
//! so the ratio here is a lower bound on the ratio at tip, not a prediction of
//! it — see
//! `docs/solutions/best-practices/small-window-benchmarks-do-not-predict-at-scale-throughput.md`.
//!
//! Two positions are benchmarked because the scan is position-dependent and the
//! index is not: `first_block` is the scan's best case (it stops immediately)
//! and `last_block` is its worst. Reporting only the worst would overstate the
//! win; reporting only the best would hide it.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]
// A benchmark fixture that fails to build has no meaningful degraded mode: a
// handler returning `Err` would be timed as a fast early return and reported as
// a win. Panicking is the correct outcome, so `expect` is deliberate here.
#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;

use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::{
    Amount, Block, CompactTarget, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut,
    Txid, Witness, absolute, block, transaction,
};
use bitcoin_rs_index::{BlockSource, Indexer};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::{
    BlockBodySource, BlockRecord, Context, Handler, TxIndexInfo, TxIndexQuery, TxQueryError,
};
use bitcoin_rs_storage::RocksDbStore;
use bitcoin_rs_storage::block_file::{BlockFilePosition, FlatFileBlockStore};
use criterion::{Criterion, criterion_group, criterion_main};
use sonic_rs::{JsonValueTrait as _, json};

/// The two fixture shapes, as (blocks, transactions per block).
///
/// One shape cannot answer the question. With 8 tiny transactions the per-record
/// cost is the file open and read, which understates a real chain; with 500 it is
/// the deserialize-and-hash of the body, which is what a mainnet block actually
/// costs. Reporting the slope at both bounds the extrapolation from either side.
/// Block counts differ so each shape stays inside a Criterion run.
const FIXTURE_SHAPES: [(u32, usize); 2] = [(2_000, 8), (200, 500)];
/// Fixture blocks start above the heights any real chain constant refers to, so
/// nothing here can be mistaken for mainnet data.
const BASE_HEIGHT: u32 = 1_000_000;

/// Serves fixture bodies out of the flat block files, paying the real syscalls.
struct FlatFileBodySource {
    files: FlatFileBlockStore,
    positions: HashMap<u32, (BlockFilePosition, [u8; 32])>,
}

impl BlockBodySource for FlatFileBodySource {
    fn block_body(&self, height: u32, _hash: Hash256) -> Option<Vec<u8>> {
        let (position, hash) = self.positions.get(&height)?;
        self.files.load(*position, height, *hash).ok()?
    }
}

impl BlockSource for FlatFileBodySource {
    fn block_at_height(&self, height: u32) -> Option<Block> {
        let bytes = self.block_body(height, Hash256::from_le_bytes(&[0_u8; 32]))?;
        bitcoin::consensus::encode::deserialize(&bytes).ok()
    }
}

/// The `after` arm's index, wired the way production wires the real one.
///
/// The handler now talks to `TxIndexQuery`, whose production implementor lives
/// in `bitcoin-rs-node` and cannot be reached from here without a dependency
/// cycle. This stands in for it over the *same* RocksDB index and the *same*
/// flat block files, so the measured cost is a real row lookup plus a real body
/// read — not a `HashMap` hit, which would zero out the index's own cost and
/// inflate the reported win.
///
/// One deliberate difference: `resolve_tx_with_height` fetches the whole
/// candidate block, while the production engine reads only the bytes a stored
/// position names. This arm is therefore *slower* than production, so the
/// measured win is a floor rather than a claim.
struct FixtureIndexQuery {
    indexer: Indexer<RocksDbStore>,
    source: Arc<FlatFileBodySource>,
}

impl TxIndexQuery for FixtureIndexQuery {
    fn transaction(&self, _txid: &Txid) -> Result<Option<Transaction>, TxQueryError> {
        unreachable!("gettxoutproof does not materialize transactions")
    }

    fn outpoint_value(&self, _outpoint: &bitcoin::OutPoint) -> Result<Option<u64>, TxQueryError> {
        unreachable!("gettxoutproof does not resolve prevout values")
    }

    fn index_info(&self) -> Result<TxIndexInfo, TxQueryError> {
        Ok(TxIndexInfo {
            synced: true,
            best_block_height: 0,
        })
    }

    fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
        self.indexer
            .resolve_tx_with_height(*txid, self.source.as_ref())
            .map(|found| found.map(|(_, height)| height))
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))
    }
}

fn empty_header() -> block::Header {
    block::Header {
        version: block::Version::TWO,
        prev_blockhash: bitcoin::BlockHash::all_zeros(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: 0,
        bits: CompactTarget::from_consensus(0x1d00_ffff),
        nonce: 0,
    }
}

/// A transaction whose txid is a function of its seed, so every fixture
/// transaction is distinct and the index has real work to disambiguate.
fn filler_tx(seed: u64) -> Transaction {
    let mut script = [0_u8; 32];
    script[..8].copy_from_slice(&seed.to_le_bytes());
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(seed.to_le_bytes().to_vec()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(script.to_vec()),
        }],
    }
}

struct Fixture {
    // Held for their `Drop`: the RocksDB and block-file directories must outlive
    // the index and the body source.
    _dir: tempfile::TempDir,
    _blocks_dir: tempfile::TempDir,
    /// Context with a populated txindex: the `after` arm.
    indexed: Arc<Context>,
    /// Context with no `tx_index` at all: the `before` arm.
    scanning: Arc<Context>,
    /// Txid planted in the first fixture block — the scan's best case.
    first_txid: Txid,
    /// Txid planted in the last fixture block — the scan's worst case.
    last_txid: Txid,
}

fn build_fixture(fixture_blocks: u32, txs_per_block: usize) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let blocks_dir = tempfile::tempdir().expect("blocks tempdir");
    let store = Arc::new(RocksDbStore::open(dir.path()).expect("open rocksdb"));
    let files = FlatFileBlockStore::open(blocks_dir.path()).expect("open block files");
    let mut indexer = Indexer::new(store);

    let mut positions = HashMap::new();
    let mut records = Vec::with_capacity(fixture_blocks as usize);
    let mut first_txid = None;
    let mut last_txid = None;

    for index in 0..fixture_blocks {
        let height = BASE_HEIGHT + index;
        let txdata = (0..txs_per_block)
            .map(|slot| {
                let seed = u64::from(height)
                    .wrapping_mul(1_000_003)
                    .wrapping_add(u64::try_from(slot).unwrap_or(0));
                filler_tx(seed)
            })
            .collect::<Vec<_>>();

        let mut block = Block {
            header: empty_header(),
            txdata,
        };
        if let Some(root) = block.compute_merkle_root() {
            block.header.merkle_root = root;
        }

        let planted = block
            .txdata
            .first()
            .map(Transaction::compute_txid)
            .expect("fixture block has transactions");
        if index == 0 {
            first_txid = Some(planted);
        }
        last_txid = Some(planted);

        let bytes = serialize(&block);
        indexer
            .ingest_block(&bytes, height)
            .expect("ingest fixture block");
        let hash = block.block_hash().to_byte_array();
        let position = files
            .persist(None, height, hash, &bytes)
            .expect("persist fixture body");
        positions.insert(height, (position, hash));
        records.push(BlockRecord::synthetic(
            height,
            Hash256::from_le_bytes(&hash),
        ));
    }

    let source = Arc::new(FlatFileBodySource { files, positions });

    let scanning = Arc::new(Context::new().with_block_body_source(Arc::clone(&source) as Arc<_>));
    for record in &records {
        scanning.add_block(record.clone());
    }

    let mut indexed_ctx = Context::new().with_block_body_source(Arc::clone(&source) as Arc<_>);
    indexed_ctx.tx_index = Some(Arc::new(FixtureIndexQuery { indexer, source }));
    let indexed = Arc::new(indexed_ctx);
    for record in records {
        indexed.add_block(record);
    }

    let first_txid = first_txid.expect("at least one fixture block");
    let last_txid = last_txid.expect("at least one fixture block");

    // A fixture where either arm fails would benchmark an error return and
    // report a spectacular, meaningless speedup. Prove both answer first.
    for (label, ctx) in [("scan", &scanning), ("index", &indexed)] {
        for (position, txid) in [("first", first_txid), ("last", last_txid)] {
            let proof = dispatch_proof(ctx, txid);
            assert!(
                proof.as_str().is_some(),
                "{label} arm returned no proof for the {position} block"
            );
        }
    }

    // The two arms must agree, or the benchmark is timing two different answers.
    assert_eq!(
        dispatch_proof(&scanning, last_txid).as_str(),
        dispatch_proof(&indexed, last_txid).as_str(),
        "the arms disagree; the benchmark would be meaningless"
    );

    Fixture {
        _dir: dir,
        _blocks_dir: blocks_dir,
        indexed,
        scanning,
        first_txid,
        last_txid,
    }
}

fn dispatch_proof(ctx: &Arc<Context>, txid: Txid) -> sonic_rs::Value {
    Handler::new(Arc::clone(ctx))
        .dispatch("gettxoutproof", &json!([[txid.to_string()]]))
        .expect("gettxoutproof failed")
}

fn bench_txoutproof(c: &mut Criterion) {
    let mut group = c.benchmark_group("gettxoutproof");
    // The scan arm reads every block body before the last one, so a single
    // iteration is already milliseconds and the default sample size would run for
    // minutes without saying anything more.
    group.sample_size(20);

    for (fixture_blocks, txs_per_block) in FIXTURE_SHAPES {
        let fixture = build_fixture(fixture_blocks, txs_per_block);
        let shape = format!("{fixture_blocks}x{txs_per_block}tx");

        for (position, txid) in [
            ("first_block", fixture.first_txid),
            ("last_block", fixture.last_txid),
        ] {
            group.bench_function(format!("before_scan/{shape}/{position}"), |b| {
                b.iter(|| black_box(dispatch_proof(&fixture.scanning, txid)));
            });
            group.bench_function(format!("after_index/{shape}/{position}"), |b| {
                b.iter(|| black_box(dispatch_proof(&fixture.indexed, txid)));
            });
        }
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_txoutproof
}
criterion_main!(benches);
