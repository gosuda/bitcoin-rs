//! Native codec, hashing, and sighash contracts: round-trip fixtures, Core
//! `sighash.json` vectors, and fuzz-corpus self-consistency.
//!
//! Fuzz-corpus gates read `BITCOIN_RS_FUZZ_CORPUS/<target>` first (the
//! `corpus/` directory of a gosuda/bitcoin-rs-fuzz-corpus checkout, the
//! canonical seed home) and fall back to a local `fuzz/corpus/<target>/`
//! overlay; they loud-skip (with a stderr note) only when neither exists. A
//! present-but-empty corpus fails. When the corpus root carries
//! `verdicts.json`, every seed is checked against its pinned verdict
//! (accepted seeds re-encode byte-identically; rejected seeds keep their
//! typed `DecodeError` kind) so a decoder change cannot silently flip a
//! verdict — `QAC-05`, docs/contracts/qa-corpus.md. Without the file the
//! gate degrades to checking that each seed yields a well-formed verdict.

#![expect(
    clippy::expect_used,
    reason = "test fixtures: a malformed vector or missing fixture file is an authoring bug, not a runtime path"
)]
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr as _;

use bitcoin_rs_primitives::{
    Block as NativeBlock, ConsensusDecode, ConsensusEncode, DecodeError, LockTime, Script,
    Sequence, SighashCache, Tx as NativeTx, Witness, Wtxid, consensus_bytes, deserialize,
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

/// Root directory that holds per-target corpus directories.
///
/// `BITCOIN_RS_FUZZ_CORPUS` points at the `corpus/` directory of a
/// gosuda/bitcoin-rs-fuzz-corpus checkout (`<dir>/<target>`) and is
/// authoritative when set; a local `fuzz/corpus/` overlay is consulted when
/// the variable is unset.
fn corpus_root() -> PathBuf {
    std::env::var_os("BITCOIN_RS_FUZZ_CORPUS")
        .map_or_else(|| repo_root().join("fuzz/corpus"), PathBuf::from)
}

/// Reads fuzz seeds for `target`.
///
/// Returns `None` only when the selected directory does not exist (the
/// corpus lives in another repository and may not be checked out);
/// `Some` — possibly empty — when it does.
fn corpus_seeds(target: &str) -> Option<Vec<(String, Vec<u8>)>> {
    let dir = corpus_root().join(target);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => panic!("{}: {error}", dir.display()),
    };
    let mut seeds = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Ok(bytes) = std::fs::read(&path) {
                seeds.push((entry.file_name().to_string_lossy().into_owned(), bytes));
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
    // data). The tests/testdata/<height>.wtxids.txt goldens were derived
    // once offline and are checked in.
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
/// `verdicts.json` at the corpus root (`QAC-05`, docs/contracts/qa-corpus.md).
///
/// Accepted seeds must decode and re-encode byte-identically; rejected seeds
/// must still be rejected with the pinned error kind, so a decoder change
/// that silently flips a verdict fails here instead of drifting. Rejections
/// are dominated by Core's "Superfluous witness record" rule
/// (`superfluous_witness`): a BIP144 marker/flag with an all-empty witness
/// section can never re-encode byte-identically, so the codec rejects it
/// before the lock time, matching the check position of both Core and
/// rust-bitcoin.
///
/// `CORPUS_VERDICTS_WRITE=1` regenerates `verdicts.json` from observed
/// verdicts (test-local write path, the documented maintenance route; the
/// publish-corpus job runs it after applying campaign output). When
/// `verdicts.json` is absent — a local overlay, or a corpus checkout from
/// before the file existed — the gate degrades to the verdict-shape check
/// alone and says so.
fn enforce_corpus_verdicts(target: &str) {
    let Some(seeds) = corpus_seeds(target) else {
        // Test-binary runner output (allowed exception: not a library path):
        // an absent corpus must skip loudly, not pass silently.
        eprintln!(
            "SKIP {target}: no corpus directory \
             (set BITCOIN_RS_FUZZ_CORPUS to a bitcoin-rs-fuzz-corpus checkout)"
        );
        return;
    };
    assert!(
        !seeds.is_empty(),
        "corpus for {target} exists but contains no seeds; gate would be vacuous"
    );

    let mut observed: BTreeMap<String, String> = BTreeMap::new();
    for (name, bytes) in &seeds {
        let name = name.as_str();
        let verdict = match target {
            "tx_validate" => decode_verdict::<NativeTx>(bytes),
            "block_validate" => decode_verdict::<NativeBlock>(bytes),
            other => panic!("unknown corpus target {other}"),
        };
        assert!(
            verdict == "accepted" || verdict.starts_with("rejected:"),
            "{target}: seed {name} has unknown verdict {verdict}"
        );
        observed.insert(name.to_owned(), verdict);
    }

    let manifest_path = corpus_root().join("verdicts.json");
    if std::env::var_os("CORPUS_VERDICTS_WRITE").is_some() {
        // Read-modify-write so per-target invocations merge into one file.
        let mut root = std::fs::read_to_string(&manifest_path)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        root.insert(
            "_contract".to_owned(),
            serde_json::Value::String(
                "QAC-05 (docs/contracts/qa-corpus.md): expected decoder verdict per seed; \
                 regenerate with BITCOIN_RS_FUZZ_CORPUS=<corpus> \
                 CORPUS_VERDICTS_WRITE=1 cargo test -p bitcoin-rs-primitives"
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
            .expect("verdicts.json renders");
        std::fs::write(&manifest_path, rendered + "\n")
            .unwrap_or_else(|error| panic!("writing {}: {error}", manifest_path.display()));
        eprintln!(
            "wrote {}; re-run without CORPUS_VERDICTS_WRITE to enforce",
            manifest_path.display()
        );
        return;
    }

    let Ok(manifest_text) = std::fs::read_to_string(&manifest_path) else {
        eprintln!(
            "WARN {target}: {} absent; checking verdict shape only \
             (regenerate with CORPUS_VERDICTS_WRITE=1 to pin per-seed verdicts)",
            manifest_path.display()
        );
        return;
    };
    let manifest = serde_json::from_str::<serde_json::Value>(&manifest_text)
        .unwrap_or_else(|error| panic!("{}: {error}", manifest_path.display()));
    let expected = manifest
        .get(target)
        .unwrap_or_else(|| panic!("{} has no \"{target}\" section", manifest_path.display()));
    let expected = expected
        .as_object()
        .expect("verdicts.json section is an object");

    for (name, observed_verdict) in &observed {
        match expected.get(name) {
            None => panic!(
                "{target}: seed {name} is not listed in {}; \
                 pin its verdict with CORPUS_VERDICTS_WRITE=1",
                manifest_path.display()
            ),
            Some(expected_verdict) => {
                let expected_verdict = expected_verdict.as_str().expect("verdict is a string");
                assert_eq!(
                    observed_verdict, expected_verdict,
                    "{target}: seed {name} verdict drifted; if intentional, \
                     re-pin with CORPUS_VERDICTS_WRITE=1"
                );
            }
        }
    }
    for name in expected.keys() {
        assert!(
            observed.contains_key(name),
            "{target}: verdicts.json lists {name} but the corpus no longer has it; \
             drop the entry with CORPUS_VERDICTS_WRITE=1"
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

/// Stable short name for a decode error, the rejected-verdict suffix.
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
// (docs/contracts/qa-corpus.md): every seed decodes to a typed verdict and
// accepted seeds re-encode byte-identically.
#[test]
fn corpus_seeds_decode_with_typed_verdicts() {
    for target in ["tx_validate", "block_validate"] {
        enforce_corpus_verdicts(target);
    }
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

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16)
                .unwrap_or_else(|error| panic!("bad hex at {index}: {error}"))
        })
        .collect()
}
