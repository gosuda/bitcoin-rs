//! Bounded preserved-body audit over the production Chainstate and `BlockSync` owners.
//! Synthetic regtest workloads, not a historical-mainnet or socket/whole-node IBD campaign.
//! ```text
//! cargo bench -p bitcoin-rs-node --no-default-features --features fjall
//! --bench block_dataflow --profile quickstart -- 12 > samples.jsonl
//! ```
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss
)]

use bitcoin_rs_chain::regtest_fixture;
use bitcoin_rs_node::metrics::{CorpusIdentity, EvidenceIdentity, Sha256Hex};
use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};
use bitcoin_rs_primitives::{
    Amount, Block, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness, consensus_bytes,
    deserialize, encode::double_sha256,
};
use sha2::{Digest, Sha256};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Instant,
};

struct AuditAllocator;
static COUNT: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static REQUESTED: AtomicU64 = AtomicU64::new(0);
static BODY_SIZE_A: AtomicU64 = AtomicU64::new(0);
static BODY_SIZE_B: AtomicU64 = AtomicU64::new(0);
static BODY_ALLOCS: AtomicU64 = AtomicU64::new(0);
static BODY_REQUESTED: AtomicU64 = AtomicU64::new(0);

fn count(size: usize) {
    if COUNT.load(Ordering::Relaxed) {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        REQUESTED.fetch_add(size as u64, Ordering::Relaxed);
        if size as u64 == BODY_SIZE_A.load(Ordering::Relaxed)
            || size as u64 == BODY_SIZE_B.load(Ordering::Relaxed)
        {
            BODY_ALLOCS.fetch_add(1, Ordering::Relaxed);
            BODY_REQUESTED.fetch_add(size as u64, Ordering::Relaxed);
        }
    }
}

// SAFETY: every operation forwards the unchanged pointer/layout to System.
// Counters allocate nothing and never inspect or change an allocation.
unsafe impl GlobalAlloc for AuditAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        // SAFETY: GlobalAlloc supplies a valid layout, forwarded unchanged.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        // SAFETY: GlobalAlloc supplies a valid layout, forwarded unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: allocation pointer and its original layout are forwarded together.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count(size);
        // SAFETY: pointer, original layout and valid new size come from GlobalAlloc.
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: AuditAllocator = AuditAllocator;

fn measured<T>(f: impl FnOnce() -> T) -> (T, serde_json::Value) {
    ALLOCS.store(0, Ordering::Relaxed);
    REQUESTED.store(0, Ordering::Relaxed);
    BODY_ALLOCS.store(0, Ordering::Relaxed);
    BODY_REQUESTED.store(0, Ordering::Relaxed);
    COUNT.store(true, Ordering::Relaxed);
    let start = Instant::now();
    let result = f();
    let nanos = start.elapsed().as_nanos();
    COUNT.store(false, Ordering::Relaxed);
    let allocations = ALLOCS.load(Ordering::Relaxed);
    let requested = REQUESTED.load(Ordering::Relaxed);
    let body_allocs = BODY_ALLOCS.load(Ordering::Relaxed);
    let body_requested = BODY_REQUESTED.load(Ordering::Relaxed);
    (
        result,
        serde_json::json!({"wall_ns":nanos,"allocations_and_reallocations":allocations,"requested_bytes":requested,"body_length_bucket_allocations":body_allocs,"body_length_bucket_bytes":body_requested}),
    )
}

fn chain(kind: &str) -> Vec<Block> {
    let mut blocks = vec![Network::Regtest.genesis_block()];
    let witness = kind.starts_with("witness_");
    let many_transactions = kind.ends_with("_transactions");
    let inputs = if kind == "early_coinbase" { 0 } else { 512 };
    let last = if inputs == 0 { 32 } else { 116 };
    // OP_DROP OP_TRUE consumes a maximum-sized witness element without signatures.
    // This isolates body copying from signature throughput; signed-spend benches
    // and consensus tests own cryptographic throughput and verdicts.
    let witness_script = [0x75, 0x51];
    let script = if witness {
        [vec![0, 32], Sha256::digest(witness_script).to_vec()].concat()
    } else {
        vec![0x51]
    };
    for height in 1..=last {
        let mut coinbase = regtest_fixture::coinbase(height);
        if inputs != 0 && height <= 16 {
            let value = coinbase.outputs[0].value.to_sat() / inputs as u64;
            coinbase.outputs = vec![
                TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: Script::from_bytes(script.clone())
                };
                inputs
            ];
        }
        let mut txs = vec![coinbase];
        if inputs != 0 && height > 100 {
            let funding = &blocks[(height - 100) as usize].txs[0];
            let funding_txid = funding.txid();
            for index in 0..if many_transactions { inputs } else { 1 } {
                let input_range = if many_transactions {
                    index..index + 1
                } else {
                    0..inputs
                };
                let value = funding.outputs[input_range.clone()]
                    .iter()
                    .map(|o| o.value.to_sat())
                    .sum::<u64>()
                    - if many_transactions { 1 } else { 1000 };
                let tx = Tx {
                    version: 2,
                    lock_time: bitcoin_rs_primitives::LockTime::ZERO,
                    inputs: input_range
                        .map(|vout| TxIn {
                            previous_output: OutPoint::new(funding_txid, vout as u32),
                            script_sig: Script::new(),
                            sequence: Sequence::MAX,
                            witness: if witness {
                                Witness::from_stack(vec![vec![42; 520], witness_script.to_vec()])
                            } else {
                                Witness::new()
                            },
                        })
                        .collect(),
                    outputs: vec![TxOut {
                        value: Amount::from_sat(value),
                        script_pubkey: Script::from_bytes(vec![0x51]),
                    }],
                };
                txs.push(tx);
            }
            if witness {
                let mut leaves = vec![[0; 32]];
                leaves.extend(txs.iter().skip(1).map(|tx| *tx.wtxid().as_bytes()));
                let root = bitcoin_rs_consensus::compute_merkle_root(&mut leaves).unwrap();
                let mut preimage = [0; 64];
                preimage[..32].copy_from_slice(&root);
                let commitment = double_sha256(&preimage);
                txs[0].inputs[0].witness = Witness::from_stack(vec![vec![0; 32]]);
                txs[0].outputs.push(TxOut {
                    value: Amount::ZERO,
                    script_pubkey: Script::from_bytes(
                        [
                            vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed],
                            commitment.as_byte_array().to_vec(),
                        ]
                        .concat(),
                    ),
                });
            }
        }
        blocks.push(
            regtest_fixture::mined_block_with_prev_hash(
                blocks.last().unwrap().block_hash(),
                height,
                txs,
            )
            .unwrap(),
        );
    }
    blocks
}

#[expect(
    clippy::assertions_on_constants,
    reason = "refuse debug execution while allowing dev-profile Clippy to compile the harness"
)]
fn main() {
    assert!(
        !cfg!(debug_assertions),
        "measure an optimized profile without debug serialization assertions"
    );
    let samples = std::env::args()
        .nth(1)
        .map_or(12, |s| s.parse::<usize>().unwrap());
    for kind in [
        "early_coinbase",
        "legacy_512_inputs",
        "witness_512_inputs",
        "legacy_512_transactions",
        "witness_512_transactions",
    ] {
        let blocks = chain(kind);
        let start = if kind == "early_coinbase" { 1 } else { 101 };
        let raw: Vec<bytes::Bytes> = blocks[start..]
            .iter()
            .map(|b| bytes::Bytes::from(consensus_bytes(b)))
            .collect();
        let corpus: Vec<u8> = raw.iter().flat_map(|b| b.iter().copied()).collect();
        let sizes: std::collections::BTreeSet<_> = raw.iter().map(bytes::Bytes::len).collect();
        assert!(sizes.len() <= 2);
        BODY_SIZE_A.store(*sizes.first().unwrap() as u64, Ordering::Relaxed);
        BODY_SIZE_B.store(*sizes.last().unwrap() as u64, Ordering::Relaxed);
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.p2p.listen.clear();
        config.storage.dbcache_mb = 32;
        config.validation.mode = bitcoin_rs_chainstate::ValidationMode::Full;
        config.validation.assume_valid_height = 0;
        let mut identity = EvidenceIdentity::of_process(&config).unwrap();
        identity.corpus = Some(CorpusIdentity {
            id: kind.into(),
            manifest_sha256: Sha256Hex::digest(&corpus),
        });
        println!(
            "{}",
            serde_json::json!({"kind":kind,"identity":identity,"raw_bytes":corpus.len(),"blocks":raw.len(),"height_from":start,"height_to":blocks.len()-1,"stop_hash":blocks.last().unwrap().block_hash().to_string(),"body_sizes":sizes,"allocator":"instrumented System; all threads; requested bytes, not RSS"})
        );
        for sample in 0..=samples {
            for mode in ["commit", "sync"] {
                let dir = tempfile::tempdir().unwrap();
                let mut resolved = config.clone();
                resolved.data_dir = dir.path().join("node");
                let state = NodeState::open(resolved, None).unwrap();
                for block in &blocks[..start] {
                    state.apply_block(block).unwrap();
                }
                state
                    .chainstate()
                    .admit_headers(&blocks[start..].iter().map(|b| b.header).collect::<Vec<_>>())
                    .unwrap();
                let (inbound, decode) = measured(|| {
                    raw.iter()
                        .map(|bytes| {
                            bitcoin_rs_p2p::InboundBlock::from_decoded(
                                deserialize::<Block>(bytes).unwrap(),
                            )
                        })
                        .collect::<Vec<_>>()
                });
                let ((), apply) = measured(|| {
                    if mode == "sync" {
                        for block in inbound {
                            state.inbound_blocks_sender().send(block).unwrap();
                        }
                        for _ in 0..128 {
                            state.sync().tick();
                            if state.chainstate().applied_tip_snapshot().unwrap().height as usize
                                == blocks.len() - 1
                            {
                                break;
                            }
                        }
                    } else {
                        for block in inbound {
                            black_box(
                                state
                                    .chainstate()
                                    .begin_transition()
                                    .unwrap()
                                    .connect(&block.block, Some(block.serialized))
                                    .unwrap(),
                            );
                        }
                    }
                });
                let tip = state.chainstate().applied_tip_snapshot().unwrap();
                assert_eq!(tip.hash, blocks.last().unwrap().block_hash().0);
                println!(
                    "{}",
                    serde_json::json!({"kind":kind,"sample":sample,"warmup":sample==0,"mode":mode,"decode_and_ingress_fixture":decode,"apply":apply,"tip":tip.hash.to_string(),"height":tip.height})
                );
            }
        }
    }
}
