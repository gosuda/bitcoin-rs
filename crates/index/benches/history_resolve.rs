//! Index read-path resolver benchmark.
//!
//! Each group measures the current position-backed resolver over a
//! production-shaped flat-file fixture.
//!
//! Blocks are served from a **real `FlatFileBlockStore`**, the same path
//! production takes through `FlatFilePruneBodyStore`: open, `fstat`, seek, read.
//! An earlier revision served them from an in-memory map, which left the syscall
//! sequence out entirely and reported ratios roughly an order of magnitude too
//! large — a whole-body read and a 250-byte range read differ by only about 2x
//! once the syscalls are counted, because at these sizes the syscalls dominate,
//! not the bytes moved.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]
// A benchmark fixture that fails to build has no meaningful degraded mode: a
// resolver returning `Err` would be timed as a fast early return and reported
// as a win. Panicking is the correct outcome, so `expect` is deliberate here
// and confined to fixture setup and the timed calls' error arms.
#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;

use bitcoin_rs_index::{BlockSource, Indexer, ScriptHash};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness, consensus_bytes, deserialize,
};
use bitcoin_rs_storage::RocksDbStore;
use bitcoin_rs_storage::block_file::{BlockFilePosition, FlatFileBlockStore};
use criterion::{Criterion, criterion_group, criterion_main};
use hashbrown::HashMap;

/// Filler transactions per block for the ~250 KB shape.
const TXS_PER_BLOCK_250K: usize = 2_200;
/// Filler transactions per block for the ~1 MB shape.
const TXS_PER_BLOCK_1M: usize = 9_000;
/// First height a fixture block is placed at. Non-zero so height 0 never
/// doubles as a "missing" sentinel.
const BASE_HEIGHT: u32 = 100;

/// Block source over a real flat-file store.
///
/// Mirrors `FlatFilePruneBodyStore`: a position lookup, then
/// `FlatFileBlockStore::load` for a whole body or `load_range` for a slice. Both
/// pay the real open/`fstat`/seek/read sequence, so the ratio this harness
/// reports is one a node can actually see.
struct FlatFileBlockSource {
    files: FlatFileBlockStore,
    positions: HashMap<u32, (BlockFilePosition, [u8; 32])>,
}

impl BlockSource for FlatFileBlockSource {
    fn block_at_height(&self, height: u32) -> Option<Block> {
        let (position, hash) = self.positions.get(&height)?;
        let bytes = self.files.load(*position, height, *hash).ok()??;
        deserialize::<Block>(&bytes).ok()
    }

    fn block_bytes_at_height(&self, height: u32, offset: u32, len: u32) -> Option<Vec<u8>> {
        let (position, hash) = self.positions.get(&height)?;
        self.files
            .load_range(*position, height, *hash, offset, len)
            .ok()?
    }
}

/// One built fixture: a populated index, a matching block source, and the
/// lookup keys that address the planted transactions.
struct Fixture {
    // Held for their `Drop`: the RocksDB and block-file directories must outlive
    // the indexer and the source.
    _dir: tempfile::TempDir,
    _blocks_dir: tempfile::TempDir,
    indexer: Indexer<RocksDbStore>,
    source: FlatFileBlockSource,
    /// Scripthash planted in every fixture block.
    target: ScriptHash,
    /// Txid of the planted transaction in the **last** fixture block.
    target_txid: Txid,
    /// An outpoint of that same planted transaction.
    target_outpoint: OutPoint,
}

const fn next_u64(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

/// Fills `out` from whole LCG draws.
///
/// Taking one byte per draw would be a trap: in an LCG modulo 2^64 the low byte
/// evolves independently of the high bits, so `state & 0xff` has period 256 and
/// every generated script would collapse into 256 distinct values. That makes
/// filler scripts collide with the target and silently corrupts the fixture.
fn fill_bytes(seed: u64, out: &mut [u8]) {
    let mut state = seed;
    for chunk in out.chunks_mut(8) {
        let draw = next_u64(&mut state).to_le_bytes();
        chunk.copy_from_slice(&draw[..chunk.len()]);
    }
}

/// Builds a 22-byte P2WPKH-shaped script so scripthash computation costs what
/// it costs on mainnet rather than on a 2-byte toy script.
fn witness_script(seed: u64) -> Vec<u8> {
    let mut bytes = vec![0x00, 0x14];
    let mut program = [0_u8; 20];
    fill_bytes(seed, &mut program);
    bytes.extend_from_slice(&program);
    bytes
}

fn filler_tx(seed: u64) -> Tx {
    let mut txid_bytes = [0_u8; 32];
    fill_bytes(seed, &mut txid_bytes);
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid(Hash256::from_le_bytes(&txid_bytes)),
                vout: u32::try_from(seed & 0x3).unwrap_or(0),
            },
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(5_000),
                script_pubkey: witness_script(seed ^ 0xa5a5_a5a5).into(),
            },
            TxOut {
                value: Amount::from_sat(7_000),
                script_pubkey: witness_script(seed ^ 0x5a5a_5a5a).into(),
            },
        ],
    }
}

/// The transaction the resolvers are asked to find. Pays `target_script` so it
/// is reachable through a funding row.
fn target_tx(height: u32, target_script: &[u8]) -> Tx {
    let mut txid_bytes = [0_u8; 32];
    fill_bytes(
        u64::from(height).wrapping_mul(0x9e37_79b9_7f4a_7c15),
        &mut txid_bytes,
    );
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid(Hash256::from_le_bytes(&txid_bytes)),
                vout: 0,
            },
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(11_000),
            script_pubkey: target_script.to_vec().into(),
        }],
    }
}

fn empty_header() -> Header {
    Header {
        version: 1,
        prev_blockhash: BlockHash::default(),
        merkle_root: Hash256::default(),
        time: 0,
        bits: CompactTarget::from_consensus(0),
        nonce: 0,
    }
}

/// Builds `heights` blocks of `txs_per_block` filler transactions, each with
/// one target transaction planted at the **midpoint**.
///
/// Midpoint placement matters: `resolve_transaction` returns on first match, so
/// planting at the front would report half the scan cost the production shape
/// actually pays.
fn build_fixture(heights: u32, txs_per_block: usize) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let blocks_dir = tempfile::tempdir().expect("blocks tempdir");
    let store = Arc::new(RocksDbStore::open(dir.path()).expect("open rocksdb"));
    let files = FlatFileBlockStore::open(blocks_dir.path()).expect("open block files");
    let mut indexer = Indexer::new(store);

    let target_script = witness_script(0xdead_beef);
    let target = ScriptHash::from_script_bytes(&target_script);

    let mut positions = HashMap::new();
    let mut last_target = None;
    let midpoint = txs_per_block / 2;

    for index in 0..heights {
        let height = BASE_HEIGHT + index;
        let planted = target_tx(height, &target_script);
        let planted_txid = planted.txid();

        let mut txdata = Vec::with_capacity(txs_per_block + 1);
        for slot in 0..txs_per_block {
            if slot == midpoint {
                txdata.push(planted.clone());
            }
            let seed = u64::from(height)
                .wrapping_mul(1_000_003)
                .wrapping_add(u64::try_from(slot).unwrap_or(0));
            txdata.push(filler_tx(seed));
        }

        let block = Block {
            header: empty_header(),
            txs: txdata,
        };
        let bytes = consensus_bytes(&block);
        indexer
            .ingest_block(&bytes, height)
            .expect("ingest fixture block");
        let hash = *block.block_hash().as_bytes();
        let position = files
            .persist(None, height, hash, &bytes)
            .expect("persist fixture body");
        positions.insert(height, (position, hash));
        last_target = Some((planted_txid, OutPoint::new(planted_txid, 0)));
    }

    let (target_txid, target_outpoint) = last_target.expect("at least one fixture height");

    let source = FlatFileBlockSource { files, positions };

    // A fixture that resolves nothing would benchmark an empty loop and report
    // a spectacular, meaningless speedup. Prove it resolves before returning.
    let planted = indexer
        .resolve_script_history(target, &source)
        .expect("fixture history resolves");
    assert_eq!(
        planted.len(),
        usize::try_from(heights).unwrap_or(0),
        "fixture must plant exactly one target transaction per height"
    );
    assert!(
        indexer
            .resolve_transaction(target_txid, &source)
            .expect("fixture transaction resolves")
            .is_some(),
        "fixture target transaction must be reachable through a txid row"
    );

    Fixture {
        _dir: dir,
        _blocks_dir: blocks_dir,
        indexer,
        source,
        target,
        target_txid,
        target_outpoint,
    }
}

/// Measures the current position-backed resolvers for one fixture.
fn bench_fixture(c: &mut Criterion, label: &str, fixture: &Fixture) {
    let Fixture {
        indexer,
        source,
        target,
        target_txid,
        target_outpoint,
        ..
    } = fixture;

    let mut history = c.benchmark_group(format!("resolve_script_history/{label}"));
    history.bench_function("positioned", |b| {
        b.iter(|| {
            black_box(
                indexer
                    .resolve_script_history(black_box(*target), source)
                    .expect("resolve history"),
            )
        });
    });
    history.finish();

    let mut unspent = c.benchmark_group(format!("resolve_unspent/{label}"));
    unspent.bench_function("positioned", |b| {
        b.iter(|| {
            black_box(
                indexer
                    .resolve_unspent_outputs_with_height(black_box(*target), source)
                    .expect("resolve unspent"),
            )
        });
    });
    unspent.finish();

    let mut transaction = c.benchmark_group(format!("resolve_transaction/{label}"));
    transaction.bench_function("positioned", |b| {
        b.iter(|| {
            black_box(
                indexer
                    .resolve_transaction(black_box(*target_txid), source)
                    .expect("resolve transaction"),
            )
        });
    });
    transaction.finish();

    let mut outpoint = c.benchmark_group(format!("resolve_outpoint_value/{label}"));
    outpoint.bench_function("positioned", |b| {
        b.iter(|| {
            black_box(
                indexer
                    .resolve_outpoint_value(black_box(*target_outpoint), source)
                    .expect("resolve outpoint value"),
            )
        });
    });
    outpoint.finish();
}

fn history_resolve(c: &mut Criterion) {
    // Height sweep at the ~250 KB block shape: isolates the per-row cost, which
    // is what the position index removes.
    for heights in [1_u32, 8, 64] {
        let fixture = build_fixture(heights, TXS_PER_BLOCK_250K);
        bench_fixture(c, &format!("heights_{heights}_250k"), &fixture);
    }

    // Block-size sweep at a fixed height count: isolates the per-block scan
    // cost, which is the term that scales with mainnet block growth.
    let fixture = build_fixture(8, TXS_PER_BLOCK_1M);
    bench_fixture(c, "heights_8_1m", &fixture);
}

criterion_group! {
    name = benches;
    // These resolvers run in the millisecond range at 64 heights, so the
    // Criterion default of 100 samples would put a single group in the tens of
    // seconds. 20 is enough to separate arms that differ by more than 1.05x.
    config = Criterion::default().sample_size(20);
    targets = history_resolve
}
criterion_main!(benches);
