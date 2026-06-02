//! Diagnostic benchmark for the production transaction verifier path.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]

use std::{collections::BTreeMap, hint::black_box, str::FromStr, time::Duration};

use bitcoin::hashes::Hash as _;
use bitcoin::script::Builder;
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute, consensus, transaction,
};
use bitcoin_rs_consensus::RustValidator;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_script::VerifyFlags;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

const CORE_VECTOR_NAME: &str =
    "tx_valid.json line 419: Unknown witness program version without discouragement";
const CORE_VECTOR_HEIGHT: u32 = 1;
const CORE_VECTOR_PREVOUT_TXID: &str =
    "0000000000000000000000000000000000000000000000000000000000000100";
const CORE_VECTOR_PREVOUTS: &[(u32, &str, u64)] = &[
    (0, "51", 1_000),
    (1, "60144c9c3dfac4207d5d8cb89df5722cb3d712385e3f", 2_000),
    (2, "51", 3_000),
];
const CORE_VECTOR_TX_HEX: &str = "0100000000010300010000000000000000000000000000000000000000000000000000000000000000000000ffffffff00010000000000000000000000000000000000000000000000000000000000000100000000ffffffff00010000000000000000000000000000000000000000000000000000000000000200000000ffffffff03e8030000000000000151d0070000000000000151b80b00000000000001510002483045022100a3cec69b52cba2d2de623ffffffffff1606184ea55476c0f8189fda231bc9cbb022003181ad597f7c380a7d1c740286b1d022b8b04ded028b833282e055e03b8efef812103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc710000000000";
const CORE_VECTOR_EXCLUDED_FLAGS: &str = "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM";

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

    group.bench_function("verify_tx_core_valid_vector", |b| {
        b.iter_batched(
            core_valid_vector,
            |case| {
                let result = case.validator.verify_tx(
                    black_box(&case.tx),
                    black_box(&case.prevouts),
                    case.height,
                    case.flags,
                );
                match result {
                    Ok(()) => black_box(()),
                    Err(error) => panic!("{CORE_VECTOR_NAME} verification failed: {error}"),
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

fn core_valid_vector() -> VerifyCase {
    let txid = match Txid::from_str(CORE_VECTOR_PREVOUT_TXID) {
        Ok(txid) => txid,
        Err(error) => panic!("{CORE_VECTOR_NAME} prevout txid should parse: {error}"),
    };

    let mut prevouts = BTreeMap::new();
    for &(vout, script_hex, amount) in CORE_VECTOR_PREVOUTS {
        let script_bytes = match decode_hex(script_hex) {
            Ok(bytes) => bytes,
            Err(error) => {
                panic!("{CORE_VECTOR_NAME} prevout {vout} script hex should decode: {error}")
            }
        };
        prevouts.insert(
            OutPoint { txid, vout },
            TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: ScriptBuf::from_bytes(script_bytes),
            },
        );
    }

    let tx_bytes = match decode_hex(CORE_VECTOR_TX_HEX) {
        Ok(bytes) => bytes,
        Err(error) => panic!("{CORE_VECTOR_NAME} transaction hex should decode: {error}"),
    };
    let tx = match consensus::deserialize(&tx_bytes) {
        Ok(tx) => Tx(tx),
        Err(error) => panic!("{CORE_VECTOR_NAME} transaction should deserialize: {error}"),
    };
    let flags = core_valid_vector_flags();

    let case = VerifyCase {
        validator: RustValidator::new(Network::Signet),
        tx,
        prevouts,
        height: CORE_VECTOR_HEIGHT,
        flags,
    };
    if let Err(error) = case
        .validator
        .verify_tx(&case.tx, &case.prevouts, case.height, case.flags)
    {
        panic!("{CORE_VECTOR_NAME} should verify before benchmarking: {error}");
    }
    case
}

fn core_valid_vector_flags() -> VerifyFlags {
    let excluded = match VerifyFlags::from_core_names(CORE_VECTOR_EXCLUDED_FLAGS) {
        Ok(flags) => flags,
        Err(error) => panic!("{CORE_VECTOR_NAME} excluded flags should parse: {error}"),
    };
    let active = VerifyFlags::from_bits(VerifyFlags::STANDARD.bits() & !excluded.bits());
    assert!(
        !active.contains(VerifyFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM),
        "{CORE_VECTOR_NAME} excluded flag must not be active",
    );
    assert!(
        active.contains(VerifyFlags::WITNESS),
        "{CORE_VECTOR_NAME} non-excluded standard flag must remain active",
    );
    active
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();
    while let Some(high) = chars.next() {
        let low = chars
            .next()
            .ok_or_else(|| format!("odd-length hex string at high nibble '{high}'"))?;
        let high = hex_nibble(high)?;
        let low = hex_nibble(low)?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(ch: char) -> Result<u8, String> {
    let value = ch
        .to_digit(16)
        .ok_or_else(|| format!("invalid hex character '{ch}'"))?;
    u8::try_from(value).map_err(|error| format!("hex nibble conversion failed: {error}"))
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
