#![allow(missing_docs)]
#![allow(clippy::expect_used, reason = "frozen bench fixtures")]

use std::hint::black_box;
use std::time::Duration;

use bitcoin_hashes::{Hash as _, hash160};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Sighash, SighashCache, Tx, TxIn, TxOut,
    Txid, Witness, deserialize,
};
use bitcoin_rs_script::{
    PreparedTransaction, ScriptErrCode, ScriptError, SignatureCache, VerifyFlags,
};
use criterion::measurement::WallTime;
use criterion::{BatchSize, BenchmarkGroup, Criterion, SamplingMode, criterion_group};
use secp256k1::{Message, PublicKey, SECP256K1, SecretKey};

const INNER_REPS: usize = 64;
const SAMPLE_SIZE: usize = 10;
const WARM_UP_SECS: u64 = 1;
const MEASURE_SECS: u64 = 20;
const ECDSA_EXTRA_SEED: u8 = 75;
const SCHNORR_EXTRA_SEED: u8 = 165;
const ECDSA_FIRST_SEED: u8 = 11;
const SCHNORR_FIRST_SEED: u8 = 101;
const ECDSA_VALUE_SAT: u64 = 100_000;
const ECDSA_OUT_SAT: u64 = 90_000;
const SCHNORR_VALUE_SAT: u64 = 100_000;
const SCHNORR_OUT_SAT: u64 = 90_000;

struct Case {
    tx: Tx,
    rows: Vec<(OutPoint, TxOut)>,
}

fn ecdsa_secret(seed_byte: u8) -> SecretKey {
    SecretKey::from_slice(&[seed_byte; 32]).expect("fixed ecdsa secret")
}

fn p2wpkh_program_and_code(pubkey_compressed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let hash20 = hash160::Hash::hash(pubkey_compressed);
    let digest = hash20.as_byte_array();
    let mut program = Vec::with_capacity(22);
    program.push(0x00);
    program.push(0x14);
    program.extend_from_slice(digest);
    let mut code = Vec::with_capacity(25);
    code.push(0x76);
    code.push(0xa9);
    code.push(0x14);
    code.extend_from_slice(digest);
    code.push(0x88);
    code.push(0xac);
    (program, code)
}

fn ecdsa_case(tx_seed: u8, sig_seed: u8) -> Case {
    let key = ecdsa_secret(tx_seed);
    let pubkey = PublicKey::from_secret_key(SECP256K1, &key)
        .serialize()
        .to_vec();
    let (program, code) = p2wpkh_program_and_code(&pubkey);
    let mut txid_bytes = [0u8; 32];
    txid_bytes[0] = tx_seed;
    txid_bytes[31] = 0xEC;
    let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&txid_bytes)), 0);
    let unsigned = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(ECDSA_OUT_SAT),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
    };
    let digest = SighashCache::new(&unsigned)
        .segwit_v0_signature_hash(0, &code, Amount::from_sat(ECDSA_VALUE_SAT), Sighash::All)
        .expect("bip143 digest");
    let signing = ecdsa_secret(sig_seed);
    let mut sig = SECP256K1.sign_ecdsa(&Message::from_digest(*digest.as_byte_array()), &signing);
    sig.normalize_s();
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(0x01);
    let witness = vec![sig_bytes, pubkey];
    let mut tx = unsigned;
    tx.inputs[0].witness = witness.into();
    let prevout = TxOut {
        value: Amount::from_sat(ECDSA_VALUE_SAT),
        script_pubkey: Script::from_bytes(program),
    };
    let rows = vec![(outpoint, prevout)];
    Case { tx, rows }
}

fn schnorr_case(seed_byte: u8) -> Case {
    use bitcoin::secp256k1::{Keypair, Message as OracleMessage, Secp256k1};
    use bitcoin::sighash::{Prevouts, SighashCache as OracleCache, TapSighashType};

    let secp = Secp256k1::new();
    let secret =
        bitcoin::secp256k1::SecretKey::from_slice(&[seed_byte; 32]).expect("fixed schnorr secret");
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let tweaked = bitcoin::key::TapTweak::tap_tweak(keypair, &secp, None);
    let (output_key, _) = tweaked.public_parts();
    let oracle_prevout = bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(SCHNORR_VALUE_SAT),
        script_pubkey: bitcoin::ScriptBuf::new_p2tr_tweaked(output_key),
    };
    let mut oracle = bitcoin::Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array([seed_byte; 32]),
                vout: 0,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(SCHNORR_OUT_SAT),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };
    let hash = OracleCache::new(&oracle)
        .taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&oracle_prevout)),
            TapSighashType::Default,
        )
        .expect("oracle bip341 digest");
    let signature = secp.sign_schnorr_no_aux_rand(
        &OracleMessage::from_digest(*bitcoin::hashes::Hash::as_byte_array(&hash)),
        tweaked.as_keypair(),
    );
    oracle.input[0].witness = bitcoin::Witness::from_slice(&[signature.serialize()]);
    let tx: Tx = deserialize(&bitcoin::consensus::serialize(&oracle)).expect("native decode");
    let prevout = TxOut {
        value: Amount::from_sat(SCHNORR_VALUE_SAT),
        script_pubkey: Script::from_bytes(oracle_prevout.script_pubkey.as_bytes().to_vec()),
    };
    let rows = vec![(tx.inputs[0].previous_output, prevout)];
    Case { tx, rows }
}

fn repetition_flags(repetition: usize) -> VerifyFlags {
    if repetition.is_multiple_of(2) {
        VerifyFlags::STANDARD
    } else {
        VerifyFlags::MANDATORY
    }
}

fn assert_valid(prepared: &PreparedTransaction<'_>, label: &str) {
    assert_eq!(
        prepared.verify_input(0, VerifyFlags::STANDARD, None),
        Ok(true),
        "{label} under STANDARD"
    );
    assert_eq!(
        prepared.verify_input(0, VerifyFlags::MANDATORY, None),
        Ok(true),
        "{label} under MANDATORY"
    );
}

struct EcdsaFixtures {
    hit: Case,
    miss: Vec<Case>,
}

struct SchnorrFixtures {
    hit: Case,
    miss: Vec<Case>,
}

fn ecdsa_fixtures() -> EcdsaFixtures {
    let hit = ecdsa_case(ECDSA_FIRST_SEED, ECDSA_FIRST_SEED);
    let hit_prepared = PreparedTransaction::new(&hit.tx, &hit.rows).expect("ecdsa hit prevouts");
    assert_valid(&hit_prepared, "ecdsa hit");

    let miss: Vec<Case> = (0u8..)
        .take(INNER_REPS)
        .map(|i| {
            let seed = ECDSA_FIRST_SEED.wrapping_add(i);
            ecdsa_case(seed, seed)
        })
        .collect();
    let miss_prepared: Vec<PreparedTransaction<'_>> = miss
        .iter()
        .map(|case| PreparedTransaction::new(&case.tx, &case.rows).expect("ecdsa miss prevouts"))
        .collect();
    for (i, prepared) in miss_prepared.iter().enumerate() {
        assert_valid(prepared, &format!("ecdsa miss {i}"));
    }
    assert_eq!(
        miss_prepared.len(),
        INNER_REPS,
        "miss arm matches the hit repetition count"
    );

    let bad = ecdsa_case(ECDSA_FIRST_SEED, 0xFE);
    let bad_prepared = PreparedTransaction::new(&bad.tx, &bad.rows).expect("ecdsa bad prevouts");
    assert_eq!(
        bad_prepared.verify_input(0, VerifyFlags::MANDATORY, None),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::EvalFalse
        }),
        "wrong-key ecdsa under MANDATORY"
    );
    assert_eq!(
        bad_prepared.verify_input(0, VerifyFlags::STANDARD, None),
        Err(ScriptError::Invalid {
            code: ScriptErrCode::SigNullFail
        }),
        "wrong-key ecdsa under STANDARD"
    );
    EcdsaFixtures { hit, miss }
}

fn schnorr_fixtures() -> SchnorrFixtures {
    let hit = schnorr_case(SCHNORR_FIRST_SEED);
    let hit_prepared = PreparedTransaction::new(&hit.tx, &hit.rows).expect("schnorr hit prevouts");
    assert_valid(&hit_prepared, "schnorr hit");

    let miss: Vec<Case> = (0u8..)
        .take(INNER_REPS)
        .map(|i| schnorr_case(SCHNORR_FIRST_SEED.wrapping_add(i)))
        .collect();
    let miss_prepared: Vec<PreparedTransaction<'_>> = miss
        .iter()
        .map(|case| PreparedTransaction::new(&case.tx, &case.rows).expect("schnorr miss prevouts"))
        .collect();
    for (i, prepared) in miss_prepared.iter().enumerate() {
        assert_valid(prepared, &format!("schnorr miss {i}"));
    }

    let bad = schnorr_negative_case(&hit);
    let bad_prepared = PreparedTransaction::new(&bad.tx, &bad.rows).expect("schnorr bad prevouts");
    for flags in [VerifyFlags::MANDATORY, VerifyFlags::STANDARD] {
        assert_eq!(
            bad_prepared.verify_input(0, flags, None),
            Err(ScriptError::Invalid {
                code: ScriptErrCode::SchnorrSig
            }),
            "flipped schnorr byte under {flags:?}"
        );
    }
    SchnorrFixtures { hit, miss }
}

fn register_ecdsa(group: &mut BenchmarkGroup<WallTime>, fixtures: &EcdsaFixtures) {
    let hit_prepared =
        PreparedTransaction::new(&fixtures.hit.tx, &fixtures.hit.rows).expect("ecdsa hit prevouts");
    let miss_prepared: Vec<PreparedTransaction<'_>> = fixtures
        .miss
        .iter()
        .map(|case| PreparedTransaction::new(&case.tx, &case.rows).expect("ecdsa miss prevouts"))
        .collect();
    let hit_cache = SignatureCache::new();
    assert_eq!(
        hit_prepared.verify_input(0, VerifyFlags::STANDARD, Some(&hit_cache)),
        Ok(true),
        "ecdsa hit warmup under STANDARD"
    );
    assert_eq!(
        hit_prepared.verify_input(0, VerifyFlags::MANDATORY, Some(&hit_cache)),
        Ok(true),
        "ecdsa hit warmup under MANDATORY"
    );
    group.bench_function("ecdsa/hit", |b| {
        b.iter(|| {
            let mut ok = 0u32;
            for i in 0..INNER_REPS {
                if hit_prepared
                    .verify_input(0, repetition_flags(i), Some(&hit_cache))
                    .is_ok()
                {
                    ok += 1;
                }
            }
            black_box(ok)
        });
    });
    group.bench_function("ecdsa/miss", |b| {
        b.iter_batched(
            SignatureCache::new,
            |cache| {
                let mut ok = 0u32;
                for (i, prepared) in miss_prepared.iter().enumerate() {
                    if prepared
                        .verify_input(0, repetition_flags(i), Some(&cache))
                        .is_ok()
                    {
                        ok += 1;
                    }
                }
                black_box(ok)
            },
            BatchSize::SmallInput,
        );
    });
}

fn register_schnorr(group: &mut BenchmarkGroup<WallTime>, fixtures: &SchnorrFixtures) {
    let hit_prepared = PreparedTransaction::new(&fixtures.hit.tx, &fixtures.hit.rows)
        .expect("schnorr hit prevouts");
    let miss_prepared: Vec<PreparedTransaction<'_>> = fixtures
        .miss
        .iter()
        .map(|case| PreparedTransaction::new(&case.tx, &case.rows).expect("schnorr miss prevouts"))
        .collect();
    let hit_cache = SignatureCache::new();
    assert_eq!(
        hit_prepared.verify_input(0, VerifyFlags::STANDARD, Some(&hit_cache)),
        Ok(true),
        "schnorr hit warmup under STANDARD"
    );
    assert_eq!(
        hit_prepared.verify_input(0, VerifyFlags::MANDATORY, Some(&hit_cache)),
        Ok(true),
        "schnorr hit warmup under MANDATORY"
    );
    group.bench_function("schnorr/hit", |b| {
        b.iter(|| {
            let mut ok = 0u32;
            for i in 0..INNER_REPS {
                if hit_prepared
                    .verify_input(0, repetition_flags(i), Some(&hit_cache))
                    .is_ok()
                {
                    ok += 1;
                }
            }
            black_box(ok)
        });
    });
    group.bench_function("schnorr/miss", |b| {
        b.iter_batched(
            SignatureCache::new,
            |cache| {
                let mut ok = 0u32;
                for (i, prepared) in miss_prepared.iter().enumerate() {
                    if prepared
                        .verify_input(0, repetition_flags(i), Some(&cache))
                        .is_ok()
                    {
                        ok += 1;
                    }
                }
                black_box(ok)
            },
            BatchSize::SmallInput,
        );
    });
}

fn signature_verification(c: &mut Criterion) {
    let ecdsa = ecdsa_fixtures();
    let schnorr = schnorr_fixtures();
    let mut group = c.benchmark_group("signature_verification");
    group.sample_size(SAMPLE_SIZE);
    group.sampling_mode(SamplingMode::Flat);
    group.warm_up_time(Duration::from_secs(WARM_UP_SECS));
    group.measurement_time(Duration::from_secs(MEASURE_SECS));

    register_ecdsa(&mut group, &ecdsa);
    register_schnorr(&mut group, &schnorr);
    group.finish();
}

fn schnorr_negative_case(hit: &Case) -> Case {
    let mut bad_tx = hit.tx.clone();
    bad_tx.inputs[0].witness[0][0] ^= 0x01;
    Case {
        tx: bad_tx,
        rows: hit.rows.clone(),
    }
}

fn assert_valid_equivalence(
    prepared: &PreparedTransaction<'_>,
    label: &str,
    cache: &SignatureCache,
) {
    for flags in [VerifyFlags::STANDARD, VerifyFlags::MANDATORY] {
        let uncached = prepared.verify_input(0, flags, None);
        assert_eq!(uncached, Ok(true), "{label} uncached under {flags:?}");
        let cached = prepared.verify_input(0, flags, Some(cache));
        assert_eq!(
            cached, uncached,
            "{label} cached/no-cache equivalence under {flags:?}"
        );
    }
}

fn assert_invalid_equivalence(
    prepared: &PreparedTransaction<'_>,
    flags: VerifyFlags,
    expected_code: ScriptErrCode,
    label: &str,
    cache: &SignatureCache,
) {
    let expected: Result<bool, ScriptError> = Err(ScriptError::Invalid {
        code: expected_code,
    });
    assert_eq!(
        prepared.verify_input(0, flags, None),
        expected,
        "{label} uncached under {flags:?}"
    );
    assert_eq!(
        prepared.verify_input(0, flags, Some(cache)),
        expected,
        "{label} cached under {flags:?}"
    );
}

fn mrp_verify() {
    let ecdsa = ecdsa_fixtures();
    let schnorr = schnorr_fixtures();
    assert_eq!(ecdsa.miss.len(), INNER_REPS, "ecdsa miss count");
    assert_eq!(schnorr.miss.len(), INNER_REPS, "schnorr miss count");
    println!("mrp-verify: fixtures ok ({INNER_REPS} ecdsa miss, {INNER_REPS} schnorr miss)");

    let cache = SignatureCache::new();

    let bad_ecdsa = ecdsa_case(ECDSA_FIRST_SEED, 0xFE);
    let bad_ecdsa_prepared =
        PreparedTransaction::new(&bad_ecdsa.tx, &bad_ecdsa.rows).expect("ecdsa bad prevouts");
    assert_invalid_equivalence(
        &bad_ecdsa_prepared,
        VerifyFlags::MANDATORY,
        ScriptErrCode::EvalFalse,
        "wrong-key ecdsa",
        &cache,
    );
    assert_invalid_equivalence(
        &bad_ecdsa_prepared,
        VerifyFlags::STANDARD,
        ScriptErrCode::SigNullFail,
        "wrong-key ecdsa",
        &cache,
    );
    let bad_schnorr = schnorr_negative_case(&schnorr.hit);
    let bad_schnorr_prepared =
        PreparedTransaction::new(&bad_schnorr.tx, &bad_schnorr.rows).expect("schnorr bad prevouts");
    assert_invalid_equivalence(
        &bad_schnorr_prepared,
        VerifyFlags::MANDATORY,
        ScriptErrCode::SchnorrSig,
        "flipped schnorr byte",
        &cache,
    );
    assert_invalid_equivalence(
        &bad_schnorr_prepared,
        VerifyFlags::STANDARD,
        ScriptErrCode::SchnorrSig,
        "flipped schnorr byte",
        &cache,
    );
    println!("mrp-verify: negative verdict agreement ok (4 flag-cases, cached == uncached)");

    let ecdsa_hit_prepared =
        PreparedTransaction::new(&ecdsa.hit.tx, &ecdsa.hit.rows).expect("ecdsa hit prevouts");
    let schnorr_hit_prepared =
        PreparedTransaction::new(&schnorr.hit.tx, &schnorr.hit.rows).expect("schnorr hit prevouts");
    let mut valid_cases = 0u32;
    assert_valid_equivalence(&ecdsa_hit_prepared, "ecdsa hit", &cache);
    valid_cases += 1;
    for (i, case) in ecdsa.miss.iter().enumerate() {
        let prepared = PreparedTransaction::new(&case.tx, &case.rows).expect("ecdsa miss prevouts");
        assert_valid_equivalence(&prepared, &format!("ecdsa miss {i}"), &cache);
        valid_cases += 1;
    }
    assert_valid_equivalence(&schnorr_hit_prepared, "schnorr hit", &cache);
    valid_cases += 1;
    for (i, case) in schnorr.miss.iter().enumerate() {
        let prepared =
            PreparedTransaction::new(&case.tx, &case.rows).expect("schnorr miss prevouts");
        assert_valid_equivalence(&prepared, &format!("schnorr miss {i}"), &cache);
        valid_cases += 1;
    }
    println!(
        "mrp-verify: cached/no-cache equivalence ok ({valid_cases} spends x 2 flag passes, strict Ok(true))"
    );

    verify_capacity_pressure_and_refutation(
        &ecdsa_hit_prepared,
        &schnorr_hit_prepared,
        &bad_ecdsa_prepared,
        &bad_schnorr_prepared,
        &cache,
    );
    println!("mrp-verify: PASS");
}

fn verify_capacity_pressure_and_refutation(
    ecdsa_hit: &PreparedTransaction<'_>,
    schnorr_hit: &PreparedTransaction<'_>,
    bad_ecdsa: &PreparedTransaction<'_>,
    bad_schnorr: &PreparedTransaction<'_>,
    cache: &SignatureCache,
) {
    let extra_ecdsa = ecdsa_case(ECDSA_EXTRA_SEED, ECDSA_EXTRA_SEED);
    let extra_ecdsa_prepared =
        PreparedTransaction::new(&extra_ecdsa.tx, &extra_ecdsa.rows).expect("ecdsa extra prevouts");
    assert_valid_equivalence(&extra_ecdsa_prepared, "ecdsa over-capacity extra", cache);
    let extra_schnorr = schnorr_case(SCHNORR_EXTRA_SEED);
    let extra_schnorr_prepared = PreparedTransaction::new(&extra_schnorr.tx, &extra_schnorr.rows)
        .expect("schnorr extra prevouts");
    assert_valid_equivalence(
        &extra_schnorr_prepared,
        "schnorr over-capacity extra",
        cache,
    );
    assert_valid_equivalence(ecdsa_hit, "ecdsa hit after capacity", cache);
    assert_valid_equivalence(schnorr_hit, "schnorr hit after capacity", cache);
    println!(
        "mrp-verify: verdict equivalence under capacity pressure ok (132 spends through one shared cache, early hits re-verified)"
    );
    assert_invalid_equivalence(
        bad_ecdsa,
        VerifyFlags::MANDATORY,
        ScriptErrCode::EvalFalse,
        "wrong-key ecdsa repeat",
        cache,
    );
    assert_invalid_equivalence(
        bad_ecdsa,
        VerifyFlags::STANDARD,
        ScriptErrCode::SigNullFail,
        "wrong-key ecdsa repeat",
        cache,
    );
    assert_invalid_equivalence(
        bad_schnorr,
        VerifyFlags::MANDATORY,
        ScriptErrCode::SchnorrSig,
        "flipped schnorr byte repeat",
        cache,
    );
    assert_invalid_equivalence(
        bad_schnorr,
        VerifyFlags::STANDARD,
        ScriptErrCode::SchnorrSig,
        "flipped schnorr byte repeat",
        cache,
    );
    println!(
        "mrp-verify: negative verdict agreement repeats ok (4 flag-cases after capacity pressure)"
    );
}

criterion_group!(benches, signature_verification);

fn main() {
    if std::env::args().any(|arg| arg == "--mrp-verify") {
        mrp_verify();
        return;
    }
    benches();
    Criterion::default().configure_from_args().final_summary();
}
