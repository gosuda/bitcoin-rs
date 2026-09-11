//! Native codec, hashing, and sighash contracts: round-trip fixtures, Core
//! `sighash.json` vectors, and fuzz-corpus self-consistency.
//!
//! Fuzz-corpus gates loud-skip (with a stderr note) only when `fuzz/corpus/<target>/`
//! is entirely absent; a present-but-empty corpus, or seeds that all fail to parse,
//! fails. Corpus seeds are gated by the expected-verdict manifest under the
//! native-consensus-codec round-trip contract `QAC-05`
//! (docs/contracts/qa-corpus.md).

#![expect(
    clippy::expect_used,
    reason = "test fixtures: a malformed vector or missing fixture file is an authoring bug, not a runtime path"
)]
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr as _;

use bitcoin_rs_primitives::{
    Amount, Block as NativeBlock, ConsensusDecode, ConsensusEncode, DecodeError, LockTime, Script,
    Sequence, Sighash, SighashCache, Tx as NativeTx, TxOut, Witness, Wtxid, consensus_bytes,
    deserialize,
};

type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root is reachable from the primitives crate")
}

fn fixture_blocks() -> Vec<(String, Vec<u8>)> {
    let mut blocks = Vec::new();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(_) => return blocks,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "bin") {
            let name = path
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_default();
            if let Ok(bytes) = std::fs::read(&path) {
                blocks.push((name, bytes));
            }
        }
    }
    blocks.sort_by(|left, right| left.0.cmp(&right.0));
    blocks
}

/// Reads fuzz seeds from `fuzz/corpus/<target>/`.
///
/// Returns `None` when the corpus directory is entirely absent (the QA-corpora track
/// owns `fuzz/corpus` and may not have landed on this branch); `Some` — possibly empty —
/// when the directory exists.
fn corpus_seeds(target: &str) -> Option<Vec<(String, Vec<u8>)>> {
    let dir = repo_root().join("fuzz/corpus").join(target);
    let entries = std::fs::read_dir(&dir).ok()?;
    let mut seeds = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Ok(bytes) = std::fs::read(&path) {
                seeds.push((path.display().to_string(), bytes));
            }
        }
    }
    seeds.sort_by(|left, right| left.0.cmp(&right.0));
    Some(seeds)
}

fn assert_tx_roundtrip(serialized: &[u8], expected_wtxid: &str, context: &str) {
    let native = deserialize::<NativeTx>(serialized)
        .unwrap_or_else(|error| panic!("{context}: native decode failed: {error}"));
    assert_eq!(consensus_bytes(&native), serialized, "{context}: re-encode");
    assert_eq!(
        native.txid().0.as_byte_array().len(),
        32,
        "{context}: txid width"
    );
    // Golden wtxid derived independently of this codec (BIP141: double
    // SHA-256 of the full serialization; equal to the txid without witness
    // data). See tests/testdata/<height>.wtxids.txt provenance in
    // scripts/derive-wtxids.py (the fetcher keeps its two-file cache contract).
    let expected = Wtxid::from_str(expected_wtxid)
        .unwrap_or_else(|error| panic!("{context}: golden wtxid hex: {error}"));
    assert_eq!(native.wtxid(), expected, "{context}: golden wtxid");
}

#[test]
fn fixture_blocks_roundtrip_byte_identically() {
    for (name, bytes) in fixture_blocks() {
        let native = deserialize::<NativeBlock>(&bytes)
            .unwrap_or_else(|error| panic!("fixture {name}: native decode failed: {error}"));

        assert_eq!(consensus_bytes(&native), bytes, "fixture {name}: re-encode");
        let wtxid_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/testdata")
            .join(format!("{name}.wtxids.txt"));
        let expected_wtxids: Vec<String> = std::fs::read_to_string(&wtxid_path)
            .unwrap_or_else(|error| {
                panic!("fixture {name}: reading {}: {error}", wtxid_path.display())
            })
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_owned)
            .collect();
        assert_eq!(
            expected_wtxids.len(),
            native.txs.len(),
            "fixture {name}: golden wtxid count"
        );
        for (index, tx) in native.txs.iter().enumerate() {
            assert_tx_roundtrip(
                &consensus_bytes(tx),
                &expected_wtxids[index],
                &format!("fixture {name} tx {index}"),
            );
        }
    }
}

/// Expected decoder verdicts for every corpus seed, pinned in
/// `fuzz/corpus/manifest.json` (`QAC-05`, docs/contracts/qa-corpus.md).
///
/// Accepted seeds must decode and re-encode byte-identically; rejected seeds
/// must still be rejected with the pinned error kind, so a decoder change that
/// silently flips a verdict fails here instead of drifting. Rejections are
/// dominated by Core's "Superfluous witness record" rule (`superfluous_witness`):
/// a BIP144 marker/flag with an all-empty witness section can never re-encode
/// byte-identically, so the codec rejects it before the lock time, matching the
/// check position of both Core and rust-bitcoin.
///
/// `CORPUS_MANIFEST_WRITE=1` regenerates the manifest from observed verdicts
/// (test-local write path, the documented maintenance route; not a library
/// path). Without it the manifest is read-only and enforced.
fn enforce_corpus_verdicts(target: &str) {
    let Some(seeds) = corpus_seeds(target) else {
        // Test-binary runner output (allowed exception: not a library path):
        // an absent corpus must skip loudly, not pass silently.
        eprintln!(
            "SKIP {target}: fuzz/corpus/{target} is entirely absent \
             (QA corpora land via another track)"
        );
        return;
    };
    assert!(
        !seeds.is_empty(),
        "fuzz/corpus/{target} exists but contains no seeds; gate would be vacuous"
    );

    let mut observed: BTreeMap<String, String> = BTreeMap::new();
    for (path, bytes) in &seeds {
        let name = path.rsplit('/').next().unwrap_or(path).to_owned();
        let verdict = match target {
            "tx_validate" => decode_verdict::<NativeTx>(bytes),
            "block_validate" => decode_verdict::<NativeBlock>(bytes),
            other => panic!("unknown corpus target {other}"),
        };
        observed.insert(name, verdict);
    }

    let manifest_path = repo_root().join("fuzz/corpus/manifest.json");
    if std::env::var_os("CORPUS_MANIFEST_WRITE").is_some() {
        // Read-modify-write so per-target invocations merge into one manifest.
        let mut root = std::fs::read_to_string(&manifest_path)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        root.insert(
            "_contract".to_owned(),
            serde_json::Value::String(
                "QAC-05 (docs/contracts/qa-corpus.md): expected decoder verdict per seed; \
                 regenerate with CORPUS_MANIFEST_WRITE=1 cargo test -p bitcoin-rs-primitives"
                    .to_owned(),
            ),
        );
        root.insert(
            target.to_owned(),
            serde_json::Value::Object(
                observed
                    .into_iter()
                    .map(|(name, verdict)| (name, serde_json::Value::String(verdict)))
                    .collect(),
            ),
        );
        let rendered = serde_json::to_string_pretty(&serde_json::Value::Object(root))
            .expect("manifest renders");
        std::fs::write(&manifest_path, rendered + "\n")
            .unwrap_or_else(|error| panic!("writing {}: {error}", manifest_path.display()));
        eprintln!(
            "wrote {}; re-run without CORPUS_MANIFEST_WRITE to enforce",
            manifest_path.display()
        );
        return;
    }

    let manifest_text = std::fs::read_to_string(&manifest_path).unwrap_or_else(|error| {
        panic!(
            "reading {}: {error}; run CORPUS_MANIFEST_WRITE=1 to pin expected verdicts",
            manifest_path.display()
        )
    });
    let manifest = serde_json::from_str::<serde_json::Value>(&manifest_text)
        .unwrap_or_else(|error| panic!("manifest.json: {error}"));
    let expected = manifest
        .get(target)
        .unwrap_or_else(|| panic!("fuzz/corpus/manifest.json has no \"{target}\" section"));
    let expected = expected.as_object().expect("manifest section is an object");

    for (name, observed_verdict) in &observed {
        match expected.get(name) {
            None => panic!(
                "fuzz/corpus/{target}: seed {name} is not listed in manifest.json; \
                 pin its verdict with CORPUS_MANIFEST_WRITE=1"
            ),
            Some(expected_verdict) => {
                let expected_verdict = expected_verdict.as_str().expect("verdict is a string");
                assert_eq!(
                    observed_verdict, expected_verdict,
                    "fuzz/corpus/{target}: seed {name} verdict drifted; if intentional, \
                     re-pin with CORPUS_MANIFEST_WRITE=1"
                );
                assert!(
                    observed_verdict == "accepted" || observed_verdict.starts_with("rejected:"),
                    "fuzz/corpus/{target}: seed {name} has unknown verdict {observed_verdict}"
                );
            }
        }
    }
    for name in expected.keys() {
        assert!(
            observed.contains_key(name),
            "fuzz/corpus/{target}: manifest lists {name} but the corpus no longer has it; \
             drop the entry with CORPUS_MANIFEST_WRITE=1"
        );
    }
}

/// Classifies one seed: `accepted` when it decodes and re-encodes
/// byte-identically, otherwise `rejected:<error-kind>`.
fn decode_verdict<T: ConsensusDecode + ConsensusEncode>(bytes: &[u8]) -> String {
    match deserialize::<T>(bytes) {
        Ok(value) => {
            assert_eq!(
                consensus_bytes(&value),
                bytes,
                "accepted seed must re-encode byte-identically"
            );
            "accepted".to_owned()
        }
        Err(error) => format!("rejected:{}", error_kind(&error)),
    }
}

/// Stable short name for a decode error, used as the manifest verdict suffix.
fn error_kind(error: &DecodeError) -> String {
    match error {
        DecodeError::EndOfData { .. } => "end_of_data".to_owned(),
        DecodeError::Varint(_) => "varint".to_owned(),
        DecodeError::InvalidSegwitFlag { .. } => "invalid_segwit_flag".to_owned(),
        DecodeError::SuperfluousWitness => "superfluous_witness".to_owned(),
        DecodeError::TrailingBytes { .. } => "trailing_bytes".to_owned(),
    }
}

// Both corpus gates enforce the QAC-05 round-trip contract
// (docs/contracts/qa-corpus.md) through the pinned verdict manifest.
#[test]
fn tx_corpus_seeds_match_expected_verdicts() {
    enforce_corpus_verdicts("tx_validate");
}

#[test]
fn block_corpus_seeds_match_expected_verdicts() {
    enforce_corpus_verdicts("block_validate");
}

#[test]
fn malformed_input_returns_typed_errors_without_panicking() {
    let mut bad_flag = 2_i32.to_le_bytes().to_vec();
    bad_flag.extend_from_slice(&[0x00, 0x02]);
    assert_eq!(
        deserialize::<NativeTx>(&bad_flag),
        Err(DecodeError::InvalidSegwitFlag { got: 0x02 })
    );

    let mut non_canonical = 1_i32.to_le_bytes().to_vec();
    non_canonical.extend_from_slice(&[0xfd, 0x01, 0x00]);
    assert!(matches!(
        deserialize::<NativeTx>(&non_canonical),
        Err(DecodeError::Varint(
            bitcoin_rs_primitives::varint::VarintError::NonCanonical { .. }
        ))
    ));

    let tx = NativeTx {
        version: 1,
        inputs: vec![bitcoin_rs_primitives::TxIn {
            previous_output: bitcoin_rs_primitives::OutPoint::default(),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: Vec::new(),
        lock_time: LockTime::ZERO,
    };
    let mut trailing = consensus_bytes(&tx);
    trailing.push(0xff);
    assert_eq!(
        deserialize::<NativeTx>(&trailing),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );

    assert!(matches!(
        deserialize::<NativeTx>(&[]),
        Err(DecodeError::EndOfData { .. })
    ));

    let small: Vec<_> = fixture_blocks()
        .into_iter()
        .filter(|(name, _)| matches!(name.as_str(), "0" | "170"))
        .collect();
    for (name, bytes) in small {
        for len in 0..bytes.len() {
            let result = deserialize::<NativeBlock>(&bytes[..len]);
            assert!(result.is_err(), "fixture {name}: prefix len {len} decoded");
        }
        for (offset, byte) in bytes.iter().enumerate() {
            let mut corrupted = bytes.clone();
            corrupted[offset] = byte.wrapping_add(1);
            let _ = deserialize::<NativeBlock>(&corrupted);
        }
    }
}

#[test]
fn legacy_sighash_matches_core_vectors() -> Result<()> {
    let path = repo_root().join("crates/consensus/tests/vectors/sighash.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    let vectors = serde_json::from_str::<serde_json::Value>(&data)?
        .as_array()
        .expect("sighash.json is an array")
        .clone();

    let mut matched = 0_usize;
    let mut skipped_codeseparator = 0_usize;
    for vector in vectors.iter().skip(1) {
        let tx_hex = vector.get(0).and_then(|v| v.as_str()).expect("tx hex");
        let script_hex = vector.get(1).and_then(|v| v.as_str()).unwrap_or("");
        let input_index = vector
            .get(2)
            .and_then(serde_json::Value::as_u64)
            .expect("input index");
        let hash_type = vector
            .get(3)
            .and_then(serde_json::Value::as_i64)
            .expect("hash type");
        let expected = vector
            .get(4)
            .and_then(|v| v.as_str())
            .expect("expected sighash");

        let tx_bytes = hex_decode(tx_hex);
        let native_tx = deserialize::<NativeTx>(&tx_bytes)
            .unwrap_or_else(|error| panic!("vector {expected}: native decode failed: {error}"));
        let script = hex_decode(script_hex);
        #[expect(
            clippy::as_conversions,
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            reason = "sighash type is a raw 32-bit wire pattern; the truncation is the point"
        )]
        let flag = hash_type as u32;
        let input_index = usize::try_from(input_index)
            .unwrap_or_else(|error| panic!("vector {expected}: input index overflow: {error}"));

        let native_hash = SighashCache::new(&native_tx)
            .legacy_signature_hash(input_index, &script, flag)
            .unwrap_or_else(|error| panic!("vector {expected}: native sighash failed: {error}"));

        // Core's sighash.json contains OP_CODESEPARATOR vectors whose expected hash
        // assumes the interpreter-level codesep strip; this crate hashes the script
        // as-is (the interpreter strips codeseps before signing), so those entries
        // are skipped here.
        if script.contains(&0xab) {
            skipped_codeseparator = skipped_codeseparator.saturating_add(1);
            continue;
        }
        assert_eq!(
            native_hash.to_string_be(),
            expected,
            "vector {expected}: native sighash"
        );
        matched = matched.saturating_add(1);
    }
    assert_eq!(
        matched, 290,
        "Core sighash.json non-OP_CODESEPARATOR rows must keep matching; skipped {skipped_codeseparator}"
    );
    assert_eq!(
        skipped_codeseparator, 210,
        "OP_CODESEPARATOR skip count drifted; matched {matched}"
    );
    Ok(())
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture x tx x input x sighash-type sweep comparing cache to one-shot helpers"
)]
fn sighash_cache_matches_one_shot_helpers_across_fixtures() {
    let ecdsa_types = [
        Sighash::All,
        Sighash::None,
        Sighash::Single,
        Sighash::AllAnyoneCanPay,
        Sighash::NoneAnyoneCanPay,
        Sighash::SingleAnyoneCanPay,
    ];
    let taproot_types = [
        Sighash::Default,
        Sighash::All,
        Sighash::None,
        Sighash::Single,
        Sighash::AllAnyoneCanPay,
        Sighash::NoneAnyoneCanPay,
        Sighash::SingleAnyoneCanPay,
    ];

    for (name, bytes) in fixture_blocks() {
        let native_block = match deserialize::<NativeBlock>(&bytes) {
            Ok(block) => block,
            Err(_) => continue,
        };
        for (tx_index, native_tx) in native_block.txs.iter().enumerate() {
            let context = format!("block {name} tx {tx_index}");
            let mut cache = SighashCache::new(native_tx);
            let native_prevouts: Vec<TxOut> = native_tx
                .inputs
                .iter()
                .enumerate()
                .map(|(index, _)| TxOut {
                    value: Amount::from_sat(
                        1_000_u64
                            + u64::try_from(index)
                                .unwrap_or_else(|error| panic!("prevout index overflow: {error}")),
                    ),
                    script_pubkey: {
                        let mut bytes = vec![0x51, 0x20];
                        bytes.extend_from_slice(&[0x42_u8; 32]);
                        bytes.into()
                    },
                })
                .collect();
            for (input_index, native_input) in native_tx.inputs.iter().enumerate() {
                let script_code = native_input.script_sig.clone();
                let value = Amount::from_sat(
                    1_000_u64
                        + u64::try_from(input_index).unwrap_or_else(|error| {
                            panic!("{context}: input index overflow: {error}")
                        }),
                );
                for ty in ecdsa_types {
                    let cached = cache
                        .legacy_signature_hash(input_index, &script_code, u32::from(ty.to_u8()))
                        .unwrap_or_else(|error| {
                            panic!("{context} input {input_index}: cache legacy failed: {error}")
                        });
                    let one_shot =
                        Sighash::compute_legacy(native_tx, input_index, &script_code, ty)
                            .unwrap_or_else(|error| {
                                panic!(
                                    "{context} input {input_index}: one-shot legacy failed: {error}"
                                )
                            });
                    assert_eq!(
                        cached, one_shot,
                        "{context} input {input_index} legacy {ty:?}"
                    );
                    let cached_bip143 = cache
                        .segwit_v0_signature_hash(input_index, &script_code, value, ty)
                        .unwrap_or_else(|error| {
                            panic!("{context} input {input_index}: cache bip143 failed: {error}")
                        });
                    let one_shot_bip143 =
                        Sighash::compute_bip143(native_tx, input_index, &script_code, value, ty)
                            .unwrap_or_else(|error| {
                                panic!(
                                    "{context} input {input_index}: one-shot bip143 failed: {error}"
                                )
                            });
                    assert_eq!(
                        cached_bip143, one_shot_bip143,
                        "{context} input {input_index} bip143 {ty:?}"
                    );
                }
                for ty in taproot_types {
                    let cached =
                        cache.taproot_signature_hash(input_index, &native_prevouts, None, None, ty);
                    let one_shot = Sighash::compute_bip341(
                        native_tx,
                        input_index,
                        &native_prevouts,
                        ty,
                        None,
                        None,
                    );
                    match (cached, one_shot) {
                        (Ok(cached), Ok(one_shot)) => assert_eq!(
                            cached, one_shot,
                            "{context} input {input_index} taproot {ty:?}"
                        ),
                        (Err(_), Err(_)) => {}
                        (cached, one_shot) => panic!(
                            "{context} input {input_index} taproot {ty:?}: verdict mismatch \
                             (cache {:?}, one-shot {:?})",
                            cached.err().map(|error| error.to_string()),
                            one_shot.err().map(|error| error.to_string())
                        ),
                    }
                }
            }
        }
    }
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16)
                .unwrap_or_else(|error| panic!("bad hex at {index}: {error}"))
        })
        .collect()
}
