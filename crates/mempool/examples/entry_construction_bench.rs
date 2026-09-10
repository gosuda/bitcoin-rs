//! Paired `MempoolEntry` construction benchmark against main `ff965032`.
//!
//! Run with `cargo run --locked --release -p bitcoin-rs-mempool
//! --example entry_construction_bench`. Fixtures exercise serialization cost,
//! not admission validity. Samples are not a performance acceptance gate.
#![allow(clippy::expect_used)]

use std::sync::Arc;

use bitcoin_rs_mempool::MempoolEntry;
use bitcoin_rs_primitives::{OutPoint, Tx, TxIn, TxOut};
use bitcoin_rs_script::count_tx_legacy;

fn fixture(inputs: usize, script_len: usize, witness_len: Option<usize>) -> Tx {
    let mut tx = Tx {
        version: 2,
        inputs: vec![
            TxIn {
                previous_output: OutPoint::default(),
                script_sig: vec![0x51; script_len],
                sequence: 0xffff_fffd,
                witness: Vec::new(),
            };
            inputs
        ],
        outputs: vec![TxOut {
            value: 1_000,
            script_pubkey: vec![0x51; script_len],
        }],
        lock_time: 42,
    };
    if let Some(length) = witness_len {
        // Witness only on the last input also exercises mixed transactions.
        let input = tx.inputs.last_mut().expect("witness fixture input");
        input.witness = vec![vec![0x55; length]];
    }
    tx
}

// Exact original constructor, benchmark-only; no production compatibility path.
fn baseline_entry(tx: Arc<Tx>, vsize: u32, fee: u64, time: u64, height: u32) -> MempoolEntry {
    let own_size = u64::from(vsize);
    let txid = tx.txid();
    let wtxid = tx.wtxid();
    let bip141_vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
    let size = u32::try_from(tx.total_size()).unwrap_or(u32::MAX);
    let weight = tx.weight();
    let sigop_cost = count_tx_legacy(&tx);
    MempoolEntry {
        tx,
        txid,
        wtxid,
        vsize,
        bip141_vsize,
        size,
        weight,
        sigop_cost,
        fee,
        fee_rate: fee_rate(fee, own_size),
        fee_delta: 0,
        ancestor_size: own_size,
        ancestor_fee: fee,
        ancestor_fee_delta: 0,
        descendant_size: own_size,
        descendant_fee: fee,
        descendant_fee_delta: 0,
        time,
        height,
    }
}

const fn fee_rate(fee: u64, vsize: u64) -> u64 {
    if vsize == 0 {
        return 0;
    }
    fee.saturating_mul(1_000) / vsize
}

fn main() {
    use std::hint::black_box;
    use std::time::Instant;

    assert!(!cfg!(debug_assertions), "run this benchmark with --release");
    for inputs in [1, 8, 128] {
        for witness in [None, Some(72)] {
            let tx = Arc::new(fixture(inputs, 72, witness));
            let before = baseline_entry(Arc::clone(&tx), 137, 1_000, 17, 23);
            let after = MempoolEntry::new(Arc::clone(&tx), 137, 1_000, 17, 23);
            assert_eq!(before.txid, after.txid);
            assert_eq!(before.wtxid, after.wtxid);
            assert_eq!(before.weight, after.weight);
            assert_eq!(before.bip141_vsize, after.bip141_vsize);
            assert_eq!(before.size, after.size);
            drop((before, after));
            let iterations = 1_000;
            for optimized in [false, true] {
                for _ in 0..100 {
                    let entry = if optimized {
                        MempoolEntry::new(Arc::clone(&tx), 137, 1_000, 17, 23)
                    } else {
                        baseline_entry(Arc::clone(&tx), 137, 1_000, 17, 23)
                    };
                    black_box(entry);
                }
            }
            for sample in 0..7 {
                for optimized in [sample % 2 != 0, sample % 2 == 0] {
                    let started = Instant::now();
                    for _ in 0..iterations {
                        let tx = Arc::clone(black_box(&tx));
                        let entry = if optimized {
                            MempoolEntry::new(tx, 137, 1_000, 17, 23)
                        } else {
                            baseline_entry(tx, 137, 1_000, 17, 23)
                        };
                        black_box(entry);
                    }
                    let elapsed_ns = started.elapsed().as_nanos();
                    println!(
                        "entry_sample,inputs={inputs},witness={},optimized={optimized},sample={sample},iterations={iterations},elapsed_ns={elapsed_ns}",
                        witness.is_some()
                    );
                }
            }
        }
    }
}
