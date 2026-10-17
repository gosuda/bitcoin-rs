//! ECDSA/Schnorr script-verification workload for the Step 8.2 signature-cache campaign.
//!
//! Purpose: give the parent a single runnable harness that measures real script
//! verification (secp256k1 ECDSA via P2WPKH/BIP143 and Schnorr via P2TR key-path/BIP341)
//! through the consensus prepared-input API (`PreparedTransaction::verify_input`) with a
//! real admission-local `SignatureCache`. Hit arms warm one cache outside timing and run
//! every timed call as a cache hit; miss arms build a fresh `SignatureCache::new()` per
//! iteration in the untimed `iter_batched` setup and run every timed call as a cold miss.
//!
//! Arms (four benchmark ids under the `signature_verification` group):
//! - `ecdsa/hit`: one P2WPKH input verified `INNER_REPS` times, alternating
//!   `STANDARD` / `MANDATORY` per repetition (admission pass 1 under policy flags, pass 2
//!   under next-block flags).
//! - `ecdsa/miss`: `INNER_REPS` distinct P2WPKH inputs (distinct keys, outpoints, and
//!   digests), each verified once with the same alternating flag sequence.
//! - `schnorr/hit`, `schnorr/miss`: same shape for P2TR key-path spends.
//!
//! Flags: `STANDARD` is the mempool admission policy set. `MANDATORY` is the consensus
//! subset that `consensus::verify_block::verify_flags` yields at full activation
//! (P2SH | DERSIG | NULLDUMMY | CLTV | CSV | WITNESS | TAPROOT); the bench does not
//! duplicate the height/network derivation, which stays owned by consensus. A signature
//! valid under `STANDARD` is valid under `MANDATORY`, matching the admission fill-then-
//! consult direction whose cost Step 4 exposed.
//!
//! Frozen config: `SAMPLE_SIZE` samples per arm, one second of warm-up (well above three
//! warm-up iterations at millisecond-scale iteration times), three seconds of measurement
//! per arm, `INNER_REPS` verifications per iteration so each arm is millisecond-scale.
//! Setup (key generation, sighash digests, signing, transaction assembly, positive and
//! negative assertions) runs once before timing; the timer covers only `verify_input`
//! calls plus the per-iteration flag alternation. No signing runs under the timer.
//!
//! Construction reuses established in-repo patterns only: the ECDSA arm mirrors
//! `tests/segwit_v0_sighash_edges.rs` (native `SighashCache` BIP143 digest, secp256k1
//! sign with low-S normalization, P2WPKH program/script-code split); the Schnorr arm
//! mirrors `tests/verifier_boundaries.rs` (rust-bitcoin oracle tap-tweak, key-spend
//! sighash, `sign_schnorr_no_aux_rand`, native decode of the oracle bytes). No large
//! fixture is copied; constants are minimal single-spend shapes.
//!
//! Negative controls (asserted once in setup, untimed): an ECDSA witness carrying a
//! low-S-normalized valid-DER signature from a different key over the same digest fails
//! with `EvalFalse` under `MANDATORY` and `SigNullFail` under `STANDARD` (NULLFAIL
//! policy); a Schnorr witness with one flipped signature byte fails with `SchnorrSig`
//! under both flag sets.
//!
//! Command (identical for baseline and candidate; parent owns every execution):
//! `cargo bench --locked -p bitcoin-rs-script --bench signature_verification`
//!
//! Limitations: single-input spends only; P2WPKH `SIGHASH_ALL` and P2TR key-path
//! `Default` only (no P2WSH, multisig, tapscript, or other sighash types); serial
//! latency only (one check per call, below the consensus rayon dispatch threshold, so
//! no parallel-pool behaviour is measured); the miss arm pays one-time sighash
//! aggregate hashing per distinct input through its cold `SighashCache` while the hit
//! arm reuses aggregates via its retained `PreparedTransaction` (the secp operation the
//! cache targets is recomputed in both); native engine only, no kernel-oracle path; no
//! mempool admission, block connect, or fee/finality checks. Raw numbers only: no
//! speedup claim is made here; the parent gate decides.
//!
//! PERF: Criterion emits public harness items whose docs are irrelevant to the
//! benchmark report.
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
use criterion::{BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main};
use secp256k1::{Message, PublicKey, SECP256K1, SecretKey};

/// Verifications per timed iteration; identical for hit and miss arms.
const INNER_REPS: usize = 64;
/// Frozen Criterion sample count per arm (matches the `insert_fill` bench convention).
const SAMPLE_SIZE: usize = 10;
/// Frozen warm-up budget per arm (millisecond-scale iterations: far above three passes).
const WARM_UP_SECS: u64 = 1;
/// Frozen measurement budget per arm.
const MEASURE_SECS: u64 = 3;
/// First ECDSA seed byte; hit uses it, miss spans the next `INNER_REPS` bytes.
const ECDSA_FIRST_SEED: u8 = 11;
/// First Schnorr seed byte; disjoint from the ECDSA range by construction.
const SCHNORR_FIRST_SEED: u8 = 101;
/// P2WPKH prevout value committed by the BIP143 digest (satoshis).
const ECDSA_VALUE_SAT: u64 = 100_000;
/// P2WPKH spending output value; script verification does not check balance.
const ECDSA_OUT_SAT: u64 = 90_000;
/// P2TR prevout value committed by the BIP341 digest (satoshis).
const SCHNORR_VALUE_SAT: u64 = 100_000;
/// P2TR spending output value; script verification does not check balance.
const SCHNORR_OUT_SAT: u64 = 90_000;

/// One owned spend and its ordered prevout row for `PreparedTransaction::new`.
struct Case {
    tx: Tx,
    rows: Vec<(OutPoint, TxOut)>,
}

fn ecdsa_secret(seed_byte: u8) -> SecretKey {
    SecretKey::from_slice(&[seed_byte; 32]).expect("fixed ecdsa secret")
}

/// P2WPKH output program (`OP_0 <20>`) and its BIP143 script code (P2PKH template).
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

/// Single-input P2WPKH spend. `tx_seed` selects the outpoint and prevout key;
/// `sig_seed` selects the signing key (equal for a valid spend, different for the
/// wrong-key negative control). The test signature is low-S normalized so encoding
/// checks pass under `STANDARD` and any failure is the cryptographic verdict.
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

/// Single-input P2TR key-path spend, signed by the rust-bitcoin oracle exactly as
/// `tests/verifier_boundaries.rs` does (tap-tweak, key-spend sighash, deterministic
/// Schnorr signature), then decoded into the native transaction type the timed path
/// verifies. Distinct seeds give distinct keys, tweaked output keys, outpoints, and
/// digests for the miss arm.
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

/// Alternating admission flags per repetition: even repetitions run the `STANDARD`
/// policy pass, odd repetitions the `MANDATORY` next-block representative.
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

/// Owned ECDSA fixtures: the repeated hit spend and the `INNER_REPS` miss spends.
/// The wrong-key negative control is asserted inside `ecdsa_fixtures` and dropped.
struct EcdsaFixtures {
    hit: Case,
    miss: Vec<Case>,
}

/// Owned Schnorr fixtures: the repeated hit spend and the `INNER_REPS` miss spends.
/// The flipped-byte negative control is asserted inside `schnorr_fixtures` and dropped.
struct SchnorrFixtures {
    hit: Case,
    miss: Vec<Case>,
}

/// Builds every ECDSA spend and asserts the positive and negative controls.
/// Untimed setup: every signature here is created before the timer starts.
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

/// Builds every Schnorr spend and asserts the positive and negative controls.
/// Untimed setup: every signature here is created before the timer starts.
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

    let mut bad_tx = hit.tx.clone();
    bad_tx.inputs[0].witness[0][0] ^= 0x01;
    let bad = Case {
        tx: bad_tx,
        rows: hit.rows.clone(),
    };
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

/// Registers the `ecdsa/hit` and `ecdsa/miss` arms. Preparation here is untimed
/// setup; the timer covers only the `verify_input` calls. The hit arm warms one
/// real cache outside timing so every timed call is a hit; the miss arm builds a
/// fresh `SignatureCache::new()` per iteration in the untimed `iter_batched` setup
/// and consumes it in the timed body so every timed call is a cold miss.
fn register_ecdsa(group: &mut BenchmarkGroup<WallTime>, fixtures: &EcdsaFixtures) {
    let hit_prepared =
        PreparedTransaction::new(&fixtures.hit.tx, &fixtures.hit.rows).expect("ecdsa hit prevouts");
    let miss_prepared: Vec<PreparedTransaction<'_>> = fixtures
        .miss
        .iter()
        .map(|case| PreparedTransaction::new(&case.tx, &case.rows).expect("ecdsa miss prevouts"))
        .collect();
    // Warm the hit cache outside timing, one verification per flag pass as an
    // admission's first pass fills and its second pass consults. The cache key
    // omits flags, so the second warmup is already a hit.
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

/// Registers the `schnorr/hit` and `schnorr/miss` arms. Preparation here is untimed
/// setup; the timer covers only the `verify_input` calls. The hit arm warms one
/// real cache outside timing so every timed call is a hit; the miss arm builds a
/// fresh `SignatureCache::new()` per iteration in the untimed `iter_batched` setup
/// and consumes it in the timed body so every timed call is a cold miss.
fn register_schnorr(group: &mut BenchmarkGroup<WallTime>, fixtures: &SchnorrFixtures) {
    let hit_prepared = PreparedTransaction::new(&fixtures.hit.tx, &fixtures.hit.rows)
        .expect("schnorr hit prevouts");
    let miss_prepared: Vec<PreparedTransaction<'_>> = fixtures
        .miss
        .iter()
        .map(|case| PreparedTransaction::new(&case.tx, &case.rows).expect("schnorr miss prevouts"))
        .collect();
    // Warm the hit cache outside timing, one verification per flag pass as an
    // admission's first pass fills and its second pass consults. The cache key
    // omits flags, so the second warmup is already a hit.
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
    // Untimed setup lives in `ecdsa_fixtures`/`schnorr_fixtures`; the timer covers
    // only `verify_input` calls made by the registered arms.
    let ecdsa = ecdsa_fixtures();
    let schnorr = schnorr_fixtures();
    let mut group = c.benchmark_group("signature_verification");
    group.sample_size(SAMPLE_SIZE);
    group.warm_up_time(Duration::from_secs(WARM_UP_SECS));
    group.measurement_time(Duration::from_secs(MEASURE_SECS));

    register_ecdsa(&mut group, &ecdsa);
    register_schnorr(&mut group, &schnorr);
    group.finish();
}

criterion_group!(benches, signature_verification);
criterion_main!(benches);
