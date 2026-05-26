//! Diagnostic benchmark for `Interpreter::execute` boundary costs.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]

use std::{hint::black_box, time::Duration};

use bitcoin::consensus::encode;
use bitcoin::hashes::Hash as _;
use bitcoin::script::Builder;
use bitcoin::{
    Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute, transaction,
};
use bitcoin_rs_script::{Interpreter, VerifyFlags};
use criterion::{
    BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::WallTime,
};

const INPUT_COUNT: usize = 400;
const SELECTED_INPUT: usize = INPUT_COUNT - 1;
const PREVOUT_VALUE: u64 = 50_000;
const OUTPUT_VALUE: u64 = 1_000;
const SAMPLE_SIZE: usize = 20;
const MEASUREMENT_SECONDS: u64 = 3;
const WITNESS_ITEM_COUNT: usize = 4;
const WITNESS_ITEM_LEN: usize = 72;

struct SpendCase {
    tx: Transaction,
    prevout: TxOut,
    script_pubkey: ScriptBuf,
    script_sig: ScriptBuf,
    witness_vec: Vec<Vec<u8>>,
    flags: VerifyFlags,
}

fn interpreter_execute_profile(c: &mut Criterion) {
    let case = spend_case();
    let mut group = c.benchmark_group("interpreter_execute_profile");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(Duration::from_secs(MEASUREMENT_SECONDS));

    bench_witness_to_vec(&mut group, &case);
    bench_clone_mutate(&mut group, &case);
    bench_serialize_mutated(&mut group, &case);
    bench_bitcoinconsensus_verify_serialized(&mut group, &case);
    bench_interpreter_execute(&mut group, &case);

    group.finish();
}

fn bench_witness_to_vec(group: &mut BenchmarkGroup<'_, WallTime>, case: &SpendCase) {
    group.bench_function("witness_to_vec_400_input", |b| {
        b.iter(|| black_box(selected_input(&case.tx).witness.to_vec()));
    });
}

fn bench_clone_mutate(group: &mut BenchmarkGroup<'_, WallTime>, case: &SpendCase) {
    group.bench_function("clone_mutate_400_input", |b| {
        b.iter(|| black_box(cloned_spending(black_box(case))));
    });
}

fn bench_serialize_mutated(group: &mut BenchmarkGroup<'_, WallTime>, case: &SpendCase) {
    group.bench_function("serialize_mutated_400_input", |b| {
        b.iter_batched(
            || cloned_spending(case),
            |spending| black_box(encode::serialize(&spending)),
            BatchSize::SmallInput,
        );
    });
}

fn bench_bitcoinconsensus_verify_serialized(
    group: &mut BenchmarkGroup<'_, WallTime>,
    case: &SpendCase,
) {
    let spending = cloned_spending(case);
    let serialized = encode::serialize(&spending);
    let script = Script::from_bytes(case.script_pubkey.as_bytes());

    group.bench_function("bitcoinconsensus_verify_serialized_400_input", |b| {
        b.iter(|| {
            let result = script.verify_with_flags(
                SELECTED_INPUT,
                case.prevout.value,
                black_box(serialized.as_slice()),
                case.flags.consensus_bits(),
            );
            match result {
                Ok(()) => black_box(true),
                Err(error) => panic!("bitcoinconsensus verification failed: {error}"),
            }
        });
    });
}

fn bench_interpreter_execute(group: &mut BenchmarkGroup<'_, WallTime>, case: &SpendCase) {
    let interpreter = Interpreter;
    group.bench_function("interpreter_execute_400_input", |b| {
        b.iter(|| {
            let result = interpreter.execute(
                case.script_pubkey.as_bytes(),
                case.script_sig.as_bytes(),
                black_box(case.witness_vec.as_slice()),
                case.flags,
                &case.prevout,
                &case.tx,
                SELECTED_INPUT,
            );
            match result {
                Ok(value) => black_box(value),
                Err(error) => panic!("interpreter execution failed: {error}"),
            }
        });
    });
}

fn spend_case() -> SpendCase {
    let script_pubkey = op_true_script();
    let script_sig = ScriptBuf::new();
    let witness_vec = witness_vec();
    let mut tx = Transaction {
        version: transaction::Version(1),
        lock_time: absolute::LockTime::ZERO,
        input: (0..INPUT_COUNT)
            .map(|index| TxIn {
                previous_output: OutPoint {
                    txid: txid(usize_to_u64(index)),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(OUTPUT_VALUE),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    selected_input_mut(&mut tx).witness = Witness::from_slice(&witness_vec);

    SpendCase {
        tx,
        prevout: TxOut {
            value: Amount::from_sat(PREVOUT_VALUE),
            script_pubkey: script_pubkey.clone(),
        },
        script_pubkey,
        script_sig,
        witness_vec,
        flags: VerifyFlags::NONE,
    }
}

fn cloned_spending(case: &SpendCase) -> Transaction {
    let mut spending = case.tx.clone();
    let inputs = spending.input.len();
    let input = match spending.input.get_mut(SELECTED_INPUT) {
        Some(input) => input,
        None => panic!("selected input {SELECTED_INPUT} out of range for {inputs} inputs"),
    };
    input.script_sig = case.script_sig.clone();
    input.witness = Witness::from_slice(&case.witness_vec);
    spending
}

fn selected_input(tx: &Transaction) -> &TxIn {
    match tx.input.get(SELECTED_INPUT) {
        Some(input) => input,
        None => panic!(
            "selected input {SELECTED_INPUT} out of range for {} inputs",
            tx.input.len()
        ),
    }
}

fn selected_input_mut(tx: &mut Transaction) -> &mut TxIn {
    let inputs = tx.input.len();
    match tx.input.get_mut(SELECTED_INPUT) {
        Some(input) => input,
        None => panic!("selected input {SELECTED_INPUT} out of range for {inputs} inputs"),
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

criterion_group!(benches, interpreter_execute_profile);
criterion_main!(benches);
