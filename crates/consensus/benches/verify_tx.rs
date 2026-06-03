//! Transaction validation benchmarks for the portable consensus path.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::hint::black_box;

use bitcoin::hashes::Hash as _;
use bitcoin::script::Builder;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
    transaction,
};
use bitcoin_rs_consensus::verify_transaction_borrowed;
use bitcoin_rs_script::{Interpreter, VerifyFlags};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

const INPUTS: u8 = 128;

fn multi_input_true_scripts(c: &mut Criterion) {
    c.bench_function("verify_tx/multi_input_true_scripts", |b| {
        b.iter_batched(
            fixture,
            |(tx, utxos)| {
                verify_transaction_borrowed(
                    black_box(&tx),
                    black_box(&utxos),
                    1,
                    black_box(VerifyFlags::MANDATORY),
                )
                .unwrap_or_else(|error| panic!("transaction verification failed: {error}"));
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("verify_tx/interpreter_multi_input_true_scripts", |b| {
        b.iter_batched(
            fixture,
            |(tx, utxos)| {
                verify_with_interpreter_loop(black_box(&tx), black_box(&utxos));
            },
            BatchSize::SmallInput,
        );
    });
}

fn verify_with_interpreter_loop(tx: &Transaction, utxos: &BTreeMap<OutPoint, TxOut>) {
    let interpreter = Interpreter;
    for (input_index, input) in tx.input.iter().enumerate() {
        let prevout = utxos
            .get(&input.previous_output)
            .unwrap_or_else(|| panic!("missing prevout at input {input_index}"));
        let witness = input.witness.to_vec();
        interpreter
            .execute(
                prevout.script_pubkey.as_bytes(),
                input.script_sig.as_bytes(),
                &witness,
                VerifyFlags::MANDATORY,
                prevout,
                tx,
                input_index,
            )
            .unwrap_or_else(|error| panic!("interpreter verification failed: {error}"));
    }
}

fn fixture() -> (Transaction, BTreeMap<OutPoint, TxOut>) {
    let mut input = Vec::with_capacity(usize::from(INPUTS));
    let mut utxos = BTreeMap::new();
    for index in 0..INPUTS {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([index; 32]),
            vout: 0,
        };
        input.push(TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        });
        utxos.insert(
            outpoint,
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: Builder::new().push_int(1).into_script(),
            },
        );
    }

    (
        Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input,
            output: vec![TxOut {
                value: Amount::from_sat(u64::from(INPUTS) * 50),
                script_pubkey: ScriptBuf::new(),
            }],
        },
        utxos,
    )
}

criterion_group!(benches, multi_input_true_scripts);
criterion_main!(benches);
