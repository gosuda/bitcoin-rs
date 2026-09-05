//! Differential oracle tests: the native codec, hashing, and sighash algorithms must be
//! byte-identical with the `bitcoin` crate (dev-dependency) and Core's sighash vectors.
//!
//! Fuzz-corpus gates loud-skip (with a stderr note) only when `fuzz/corpus/<target>/` is
//! entirely absent; a present-but-empty corpus, or seeds that all fail to parse, fails.

#![expect(
    clippy::expect_used,
    reason = "test fixtures: a malformed vector or missing fixture file is an authoring bug, not a runtime path"
)]
use std::path::PathBuf;

use bitcoin::consensus::{deserialize as bitcoin_deserialize, serialize as bitcoin_serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::sighash::{
    Annex, EcdsaSighashType, Prevouts, SighashCache as BitcoinSighashCache, TapSighashType,
};
use bitcoin::{Amount, Block as BitcoinBlock, ScriptBuf, Transaction};

use bitcoin_rs_primitives::{
    Block as NativeBlock, DecodeError, Hash256, Sighash, SighashCache, Tx as NativeTx, TxOut,
    consensus_bytes, deserialize,
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

fn native_block_hash(hash: bitcoin::BlockHash) -> bitcoin_rs_primitives::BlockHash {
    bitcoin_rs_primitives::BlockHash(Hash256::from_le_bytes(hash.as_byte_array()))
}

/// The one sanctioned native-vs-oracle decode divergence class: a BIP144 marker/flag
/// followed by all-empty witness sections. Core's consensus decoder rejects the
/// encoding ("Superfluous witness record"); rust-bitcoin 0.32 accepts it whenever the
/// input list is non-empty. The native decoder follows Core, and fuzz-corpus garbage
/// regularly encodes the shape, so corpus gates skip these seeds loudly instead of
/// failing; every other oracle/native verdict disagreement still fails the gate.
const fn is_documented_oracle_looseness(error: &DecodeError) -> bool {
    matches!(error, DecodeError::SuperfluousWitness)
}

fn assert_tx_parity(serialized: &[u8], context: &str) {
    let oracle: Transaction = bitcoin_deserialize(serialized)
        .unwrap_or_else(|error| panic!("{context}: oracle decode failed: {error}"));
    let native = deserialize::<NativeTx>(serialized)
        .unwrap_or_else(|error| panic!("{context}: native decode failed: {error}"));

    assert_eq!(
        native.txid().0.as_byte_array(),
        oracle.compute_txid().as_byte_array(),
        "{context}: txid"
    );
    assert_eq!(
        native.wtxid().0.as_byte_array(),
        oracle.compute_wtxid().as_byte_array(),
        "{context}: wtxid"
    );
    assert_eq!(consensus_bytes(&native), serialized, "{context}: re-encode");
}

#[test]
fn fixture_blocks_are_byte_identical_with_the_oracle() {
    for (name, bytes) in fixture_blocks() {
        let oracle: BitcoinBlock = bitcoin_deserialize(&bytes)
            .unwrap_or_else(|error| panic!("fixture {name}: oracle decode failed: {error}"));
        let native = deserialize::<NativeBlock>(&bytes)
            .unwrap_or_else(|error| panic!("fixture {name}: native decode failed: {error}"));

        assert_eq!(
            native.block_hash(),
            native_block_hash(oracle.block_hash()),
            "fixture {name}: block hash"
        );
        assert_eq!(consensus_bytes(&native), bytes, "fixture {name}: re-encode");
        assert_eq!(
            native.txs.len(),
            oracle.txdata.len(),
            "fixture {name}: tx count"
        );

        for (index, oracle_tx) in oracle.txdata.iter().enumerate() {
            let serialized = bitcoin_serialize(oracle_tx);
            assert_tx_parity(&serialized, &format!("fixture {name} tx {index}"));
        }
    }
}

#[test]
fn tx_corpus_seeds_match_the_oracle() {
    let Some(seeds) = corpus_seeds("tx_validate") else {
        // Test-binary runner output (allowed exception: not a library path):
        // an absent corpus must skip loudly, not pass silently.
        eprintln!(
            "SKIP tx_corpus_seeds_match_the_oracle: fuzz/corpus/tx_validate is entirely \
             absent (QA corpora land via another track)"
        );
        return;
    };
    assert!(
        !seeds.is_empty(),
        "fuzz/corpus/tx_validate exists but contains no seeds; gate would be vacuous"
    );
    let seed_count = seeds.len();
    let mut checked = 0_usize;
    for (path, bytes) in seeds {
        let oracle = bitcoin_deserialize::<Transaction>(&bytes);
        let native = deserialize::<NativeTx>(&bytes);
        match (oracle, native) {
            (Ok(oracle_tx), Ok(native_tx)) => {
                assert_eq!(
                    native_tx.txid().0.as_byte_array(),
                    oracle_tx.compute_txid().as_byte_array(),
                    "{path}: txid"
                );
                assert_eq!(
                    native_tx.wtxid().0.as_byte_array(),
                    oracle_tx.compute_wtxid().as_byte_array(),
                    "{path}: wtxid"
                );
                assert_eq!(consensus_bytes(&native_tx), bytes, "{path}: re-encode");
                checked += 1;
            }
            (Err(_), Err(_)) => {}
            (Ok(_), Err(error)) if is_documented_oracle_looseness(&error) => {
                // Test-binary runner output (allowed exception: not a library path):
                // loud skip for the documented SuperfluousWitness divergence.
                eprintln!(
                    "SKIP {path}: oracle accepts the encoding Core rejects \
                     (documented SuperfluousWitness divergence)"
                );
            }
            (oracle, native) => panic!(
                "{path}: decode verdict mismatch (oracle {:?}, native {:?})",
                oracle.map(|_| ()).err().map(|e| e.to_string()),
                native.map(|_| ()).err().map(|e| e.to_string())
            ),
        }
    }
    assert!(
        checked > 0,
        "fuzz/corpus/tx_validate: iterated {seed_count} seed(s) but none parsed by both \
         decoders; gate would be vacuous"
    );
}

#[test]
fn block_corpus_seeds_match_the_oracle() {
    let Some(seeds) = corpus_seeds("block_validate") else {
        // Test-binary runner output (allowed exception: not a library path):
        // an absent corpus must skip loudly, not pass silently.
        eprintln!(
            "SKIP block_corpus_seeds_match_the_oracle: fuzz/corpus/block_validate is \
             entirely absent (QA corpora land via another track)"
        );
        return;
    };
    assert!(
        !seeds.is_empty(),
        "fuzz/corpus/block_validate exists but contains no seeds; gate would be vacuous"
    );
    let seed_count = seeds.len();
    let mut checked = 0_usize;
    for (path, bytes) in seeds {
        let oracle = bitcoin_deserialize::<BitcoinBlock>(&bytes);
        let native = deserialize::<NativeBlock>(&bytes);
        match (oracle, native) {
            (Ok(oracle_block), Ok(native_block)) => {
                assert_eq!(
                    native_block.block_hash(),
                    native_block_hash(oracle_block.block_hash()),
                    "{path}: block hash"
                );
                assert_eq!(consensus_bytes(&native_block), bytes, "{path}: re-encode");
                checked += 1;
            }
            (Err(_), Err(_)) => {}
            (Ok(_), Err(error)) if is_documented_oracle_looseness(&error) => {
                // Test-binary runner output (allowed exception: not a library path):
                // loud skip for the documented SuperfluousWitness divergence.
                eprintln!(
                    "SKIP {path}: oracle accepts the encoding Core rejects \
                     (documented SuperfluousWitness divergence)"
                );
            }
            (oracle, native) => panic!(
                "{path}: decode verdict mismatch (oracle {:?}, native {:?})",
                oracle.map(|_| ()).err().map(|e| e.to_string()),
                native.map(|_| ()).err().map(|e| e.to_string())
            ),
        }
    }
    assert!(
        checked > 0,
        "fuzz/corpus/block_validate: iterated {seed_count} seed(s) but none parsed by both \
         decoders; gate would be vacuous"
    );
}

#[test]
fn malformed_input_returns_typed_errors_without_panicking() {
    // Exact variant checks on hand-built malformed inputs.
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
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        outputs: Vec::new(),
        lock_time: 0,
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

    // Every truncation of a real block must fail with a typed error, never panic.
    let small: Vec<_> = fixture_blocks()
        .into_iter()
        .filter(|(name, _)| matches!(name.as_str(), "0" | "170"))
        .collect();
    for (name, bytes) in small {
        for len in 0..bytes.len() {
            let result = deserialize::<NativeBlock>(&bytes[..len]);
            assert!(result.is_err(), "fixture {name}: prefix len {len} decoded");
        }
        // Single-byte corruptions may or may not decode; they must never panic.
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
        let oracle_tx: Transaction = bitcoin_deserialize(&tx_bytes)
            .unwrap_or_else(|error| panic!("vector {expected}: oracle decode failed: {error}"));
        let native_tx = deserialize::<NativeTx>(&tx_bytes)
            .unwrap_or_else(|error| panic!("vector {expected}: native decode failed: {error}"));
        let script = hex_decode(script_hex);
        // Core writes hash_type as a signed JSON number; the wire form is its low
        // 32 bits, so the truncating read is the intended bit-exact value.
        #[expect(
            clippy::as_conversions,
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            reason = "sighash type is a raw 32-bit wire pattern; the truncation is the point"
        )]
        let flag = hash_type as u32;
        let input_index = usize::try_from(input_index)
            .unwrap_or_else(|error| panic!("vector {expected}: input index overflow: {error}"));

        let oracle_cache = BitcoinSighashCache::new(&oracle_tx);
        let oracle_hash = oracle_cache
            .legacy_signature_hash(
                input_index,
                ScriptBuf::from_bytes(script.clone()).as_script(),
                flag,
            )
            .unwrap_or_else(|error| panic!("vector {expected}: oracle sighash failed: {error}"));

        let native_hash = SighashCache::new(&native_tx)
            .legacy_signature_hash(input_index, &script, flag)
            .unwrap_or_else(|error| panic!("vector {expected}: native sighash failed: {error}"));

        assert_eq!(
            native_hash.as_byte_array(),
            oracle_hash.as_byte_array(),
            "vector {expected}: native vs oracle (flag {flag}, idx {input_index})"
        );
        // Core's sighash.json contains OP_CODESEPARATOR vectors whose expected hash
        // assumes the interpreter-level codesep strip; rust-bitcoin's oracle (and this
        // crate, whose interpreter strips codeseps before signing) hash the script
        // as-is, so those entries are compared oracle-to-oracle only.
        if script.contains(&0xab) {
            skipped_codeseparator = skipped_codeseparator.saturating_add(1);
            continue;
        }
        assert_eq!(
            native_hash.to_string_be(),
            expected,
            "vector {expected}: native sighash (oracle {oracle_hash})"
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
    reason = "the oracle sweep is one exhaustive block x tx x input x type x annex x leaf loop by design"
)]
fn sighash_matches_oracle_across_corpus() {
    let ecdsa_types = [
        (Sighash::All, EcdsaSighashType::All),
        (Sighash::None, EcdsaSighashType::None),
        (Sighash::Single, EcdsaSighashType::Single),
        (
            Sighash::AllAnyoneCanPay,
            EcdsaSighashType::AllPlusAnyoneCanPay,
        ),
        (
            Sighash::NoneAnyoneCanPay,
            EcdsaSighashType::NonePlusAnyoneCanPay,
        ),
        (
            Sighash::SingleAnyoneCanPay,
            EcdsaSighashType::SinglePlusAnyoneCanPay,
        ),
    ];
    let taproot_types = [
        (Sighash::Default, TapSighashType::Default),
        (Sighash::All, TapSighashType::All),
        (Sighash::None, TapSighashType::None),
        (Sighash::Single, TapSighashType::Single),
        (
            Sighash::AllAnyoneCanPay,
            TapSighashType::AllPlusAnyoneCanPay,
        ),
        (
            Sighash::NoneAnyoneCanPay,
            TapSighashType::NonePlusAnyoneCanPay,
        ),
        (
            Sighash::SingleAnyoneCanPay,
            TapSighashType::SinglePlusAnyoneCanPay,
        ),
    ];
    let annexes: [Option<Vec<u8>>; 2] = [None, Some(vec![0x50, 0xde, 0xad, 0xbe, 0xef])];
    let leaf: Hash256 = Hash256::from_le_bytes(&[0xa5_u8; 32]);
    let leafs: [Option<Hash256>; 2] = [None, Some(leaf)];

    let mut sources: Vec<(String, Vec<u8>)> = fixture_blocks();
    if let Some(seeds) = corpus_seeds("block_validate") {
        sources.extend(seeds);
    }

    for (name, bytes) in sources {
        let oracle_block: BitcoinBlock = match bitcoin_deserialize(&bytes) {
            Ok(block) => block,
            Err(_) => continue,
        };
        let native_block = match deserialize::<NativeBlock>(&bytes) {
            Ok(block) => block,
            Err(error) if is_documented_oracle_looseness(&error) => {
                // Test-binary runner output (allowed exception: not a library path):
                // loud skip for the documented SuperfluousWitness divergence.
                eprintln!(
                    "SKIP {name}: oracle accepts the encoding Core rejects \
                     (documented SuperfluousWitness divergence)"
                );
                continue;
            }
            Err(error) => {
                panic!("block {name}: native decode failed where oracle succeeded: {error}")
            }
        };

        for (tx_index, (oracle_tx, native_tx)) in oracle_block
            .txdata
            .iter()
            .zip(native_block.txs.iter())
            .enumerate()
        {
            let context = format!("block {name} tx {tx_index}");
            // Caches and synthetic prevouts are per-tx: midstates and prevout data are
            // reused across every input and sighash-type combination below, without
            // changing the set of digests computed.
            let mut oracle_cache = BitcoinSighashCache::new(oracle_tx);
            let mut native_cache = SighashCache::new(native_tx);
            let oracle_prevouts: Vec<bitcoin::TxOut> = native_tx
                .inputs
                .iter()
                .enumerate()
                .map(|(index, _)| bitcoin::TxOut {
                    value: Amount::from_sat(
                        1_000_u64
                            + u64::try_from(index)
                                .unwrap_or_else(|error| panic!("prevout index overflow: {error}")),
                    ),
                    script_pubkey: p2tr_style_script(),
                })
                .collect();
            let native_prevouts: Vec<TxOut> = oracle_prevouts
                .iter()
                .map(|prevout| TxOut {
                    value: prevout.value.to_sat(),
                    script_pubkey: prevout.script_pubkey.as_bytes().to_vec(),
                })
                .collect();
            for (input_index, native_input) in native_tx.inputs.iter().enumerate() {
                let script_code = native_input.script_sig.clone();
                let value = 1_000_u64
                    + u64::try_from(input_index)
                        .unwrap_or_else(|error| panic!("{context}: input index overflow: {error}"));
                let oracle_script = ScriptBuf::from_bytes(script_code.clone());
                for (ours, oracle_ty) in &ecdsa_types {
                    let oracle_hash = oracle_cache
                        .legacy_signature_hash(input_index, &oracle_script, oracle_ty.to_u32())
                        .unwrap_or_else(|error| {
                            panic!("{context} input {input_index}: oracle legacy failed: {error}")
                        });
                    let native_hash = native_cache
                        .legacy_signature_hash(input_index, &script_code, oracle_ty.to_u32())
                        .unwrap_or_else(|error| {
                            panic!("{context} input {input_index}: native legacy failed: {error}")
                        });
                    assert_eq!(
                        native_hash.as_byte_array(),
                        oracle_hash.as_byte_array(),
                        "{context} input {input_index} legacy {ours:?}"
                    );
                }

                for (ours, oracle_ty) in &ecdsa_types {
                    let oracle_hash = oracle_cache
                        .p2wsh_signature_hash(
                            input_index,
                            &oracle_script,
                            Amount::from_sat(value),
                            *oracle_ty,
                        )
                        .unwrap_or_else(|error| {
                            panic!("{context} input {input_index}: oracle bip143 failed: {error}")
                        });
                    let native_hash = native_cache
                        .segwit_v0_signature_hash(input_index, &script_code, value, *ours)
                        .unwrap_or_else(|error| {
                            panic!("{context} input {input_index}: native bip143 failed: {error}")
                        });
                    assert_eq!(
                        native_hash.as_byte_array(),
                        oracle_hash.as_byte_array(),
                        "{context} input {input_index} bip143 {ours:?}"
                    );
                }
                for (ours, oracle_ty) in &taproot_types {
                    for annex in &annexes {
                        for leaf_hash in &leafs {
                            let oracle_annex = annex
                                .as_ref()
                                .map(|bytes| Annex::new(bytes).expect("valid annex fixture"));
                            let oracle_leaf = leaf_hash.map(|hash| {
                                (
                                    bitcoin::TapLeafHash::from_byte_array(hash.to_le_bytes()),
                                    0xffff_ffff_u32,
                                )
                            });
                            let oracle_result = oracle_cache.taproot_signature_hash(
                                input_index,
                                &Prevouts::All(&oracle_prevouts),
                                oracle_annex,
                                oracle_leaf,
                                *oracle_ty,
                            );
                            let native_result = native_cache.taproot_signature_hash(
                                input_index,
                                &native_prevouts,
                                annex.as_deref(),
                                leaf_hash.map(|hash| (hash, 0xffff_ffff_u32)),
                                *ours,
                            );
                            match (oracle_result, native_result) {
                                (Ok(oracle_hash), Ok(native_hash)) => assert_eq!(
                                    native_hash.as_byte_array(),
                                    oracle_hash.as_byte_array(),
                                    "{context} input {input_index} taproot {ours:?} annex {} leaf {}",
                                    annex.is_some(),
                                    leaf_hash.is_some()
                                ),
                                (Err(_), Err(_)) => {}
                                (oracle, native) => panic!(
                                    "{context} input {input_index} taproot {ours:?}: verdict mismatch \
                                     (oracle {:?}, native {:?})",
                                    oracle.map(|_| ()).err().map(|e| e.to_string()),
                                    native.map(|_| ()).err().map(|e| e.to_string())
                                ),
                            }
                        }
                    }
                }
            }
        }
    }
}

fn p2tr_style_script() -> ScriptBuf {
    ScriptBuf::from_bytes({
        let mut bytes = vec![0x51, 0x20];
        bytes.extend_from_slice(&[0x42_u8; 32]);
        bytes
    })
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
