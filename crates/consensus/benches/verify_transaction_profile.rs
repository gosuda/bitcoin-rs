//! Diagnostic benchmark for the production transaction verifier path.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]

use std::{collections::BTreeMap, hint::black_box, time::Duration};

use bitcoin::hashes::Hash as _;
use bitcoin::script::Builder;
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute, transaction,
};
use bitcoin_rs_consensus::RustValidator;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_script::VerifyFlags;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

const INPUT_COUNT: usize = 400;
const PREVOUT_VALUE: u64 = 50_000;
const OUTPUT_VALUE: u64 = 1_000;
const SAMPLE_SIZE: usize = 10;
const MEASUREMENT_SECONDS: u64 = 5;
const WITNESS_ITEM_COUNT: usize = 4;
const WITNESS_ITEM_LEN: usize = 72;

struct VerifyCase {
    validator: RustValidator,
    tx: Tx,
    prevouts: BTreeMap<OutPoint, TxOut>,
    height: u32,
    flags: VerifyFlags,
}

fn verify_transaction_profile(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_transaction_profile");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(Duration::from_secs(MEASUREMENT_SECONDS));

    group.bench_function("verify_tx_op_true_400_input", |b| {
        b.iter_batched(
            verify_case,
            |case| {
                let result = case.validator.verify_tx(
                    black_box(&case.tx),
                    black_box(&case.prevouts),
                    case.height,
                    case.flags,
                );
                match result {
                    Ok(()) => black_box(()),
                    Err(error) => panic!("transaction verification failed: {error}"),
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn verify_case() -> VerifyCase {
    let script_pubkey = op_true_script();
    let mut prevouts = BTreeMap::new();
    let input = (0..INPUT_COUNT)
        .map(|index| {
            let outpoint = OutPoint {
                txid: txid(usize_to_u64(index)),
                vout: 0,
            };
            prevouts.insert(
                outpoint,
                TxOut {
                    value: Amount::from_sat(PREVOUT_VALUE),
                    script_pubkey: script_pubkey.clone(),
                },
            );
            TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&witness_vec()),
            }
        })
        .collect();
    let tx = Tx(Transaction {
        version: transaction::Version(1),
        lock_time: absolute::LockTime::ZERO,
        input,
        output: vec![TxOut {
            value: Amount::from_sat(OUTPUT_VALUE),
            script_pubkey: ScriptBuf::new(),
        }],
    });

    VerifyCase {
        validator: RustValidator::new(Network::Signet),
        tx,
        prevouts,
        height: 1,
        flags: VerifyFlags::NONE,
    }
}

fn op_true_script() -> ScriptBuf {
    Builder::new().push_int(1).into_script()
}

fn witness_vec() -> Vec<Vec<u8>> {
    (0..WITNESS_ITEM_COUNT)
        .map(|index| vec![usize_to_u8(index); WITNESS_ITEM_LEN])
        .collect()
}

fn txid(seed: u64) -> Txid {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(11).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0xd1b5_4a32_d192_ed03).to_le_bytes());
    Txid::from_byte_array(bytes)
}

fn usize_to_u64(value: usize) -> u64 {
    match u64::try_from(value) {
        Ok(value) => value,
        Err(error) => panic!("usize to u64 conversion failed: {error}"),
    }
}

fn usize_to_u8(value: usize) -> u8 {
    match u8::try_from(value) {
        Ok(value) => value,
        Err(error) => panic!("usize to u8 conversion failed: {error}"),
    }
}

criterion_group!(benches, verify_transaction_profile);
criterion_main!(benches);
