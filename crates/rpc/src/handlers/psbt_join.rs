//! Wallet-free joining of distinct transactions, with their PSBT maps attached.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bitcoin::Transaction;
use bitcoin::absolute::LockTime;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::rand::{Rng, seq::SliceRandom as _};
use bitcoin::transaction::Version;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value};

use crate::context::Context;
use crate::error::RpcError;
use crate::psbt::{DecodeError, PsbtBudget};

const MAX_JOIN_SOURCES: usize = 256;

const JOIN_HELP: &str = "joinpsbts [\"psbt\",...]\n\nJoins multiple distinct PSBTs with different inputs and outputs into one PSBT with inputs and outputs from all of the PSBTs\nNo input in any of the PSBTs can be in more than one of the PSBTs.\n\nArguments:\n1. txs            (json array, required) The base64 strings of partially signed transactions\n     [\n       \"psbt\",    (string, required) A base64 string of a PSBT\n       ...\n     ]\n\nResult:\n\"str\"    (string) The base64-encoded partially signed transaction\n\nExamples:\n> bitcoin-cli joinpsbts \"psbt\"\n";

pub(crate) fn joinpsbts(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let params = super::bind_named_params(params, &["txs"])?;
    let params = super::params_array(&params)?;
    if params.len() != 1 {
        return Err(RpcError::Misc(JOIN_HELP.into()));
    }
    let sources = params[0]
        .as_array()
        .ok_or_else(|| super::wrong_type(1, "txs", &params[0], "array"))?;
    if sources.len() < 2 {
        return Err(RpcError::InvalidParameter(
            "At least two PSBTs are required to join PSBTs.".into(),
        ));
    }
    if sources.len() > MAX_JOIN_SOURCES {
        return Err(RpcError::InvalidParameter(
            "joinpsbts supports at most 256 source PSBTs".into(),
        ));
    }
    // Bound the aggregate before decoding any source. Within admitted limits,
    // type/decode errors retain Core's source order. Resource refusal can take
    // precedence when a later string puts the whole request over the budget.
    let mut budget = PsbtBudget::default();
    for source in sources {
        if let Some(text) = source.as_str() {
            budget.add_encoded(text).map_err(DecodeError::into_rpc)?;
        }
    }
    let mut decoded = Vec::with_capacity(sources.len());
    for source in sources {
        let text = source
            .as_str()
            .ok_or_else(|| super::wrong_type_plain(source, "string"))?;
        let psbt = crate::psbt::decode(text).map_err(crate::psbt::DecodeError::into_rpc)?;
        budget.add_decoded(&psbt).map_err(DecodeError::into_rpc)?;
        decoded.push(psbt);
    }
    // Decode every source before duplicate detection: a malformed later PSBT
    // must not be hidden by a duplicate in an earlier one.
    let joined = assemble_join(decoded, &mut bitcoin::secp256k1::rand::thread_rng())?;
    crate::compat::convert::typed_to_sonic(&corepc_types::v31::JoinPsbts(crate::psbt::encode(
        &joined,
    )?))
}

/// PRE: each source passed the shared strict decoder and aggregate admission.
/// Maps move with their corresponding transaction entry, including duplicates
/// among outputs. Only the legacy signature fields Core clears are removed.
fn assemble_join(sources: Vec<Psbt>, rng: &mut impl Rng) -> Result<Psbt, RpcError> {
    let mut version = 1_u32;
    let mut locktime = u32::MAX;
    let mut seen = BTreeSet::new();
    let mut input_pairs = Vec::new();
    let mut output_pairs = Vec::new();
    let mut unknown = BTreeMap::new();
    for source in sources {
        let Psbt {
            unsigned_tx,
            inputs,
            outputs,
            unknown: source_unknown,
            ..
        } = source;
        // Core 31.1 transaction versions are u32. rust-bitcoin represents the
        // same wire bits as i32; a signed comparison would lose high versions.
        version = version.max(u32::from_le_bytes(unsigned_tx.version.0.to_le_bytes()));
        locktime = locktime.min(unsigned_tx.lock_time.to_consensus_u32());
        debug_assert_eq!(unsigned_tx.input.len(), inputs.len());
        debug_assert_eq!(unsigned_tx.output.len(), outputs.len());
        for (input, mut map) in unsigned_tx.input.into_iter().zip(inputs) {
            // Strict unsigned inputs have empty scriptSig/witness. Core's
            // CTxIn equality therefore reduces to prevout plus sequence,
            // allowing a repeated prevout when its sequence differs.
            if !seen.insert((input.previous_output, input.sequence.to_consensus_u32())) {
                return Err(RpcError::InvalidParameter(format!(
                    "Input {}:{} exists in multiple PSBTs",
                    input.previous_output.txid, input.previous_output.vout
                )));
            }
            map.partial_sigs.clear();
            map.final_script_sig = None;
            map.final_script_witness = None;
            input_pairs.push((input, map));
        }
        output_pairs.extend(unsigned_tx.output.into_iter().zip(outputs));
        for (key, value) in source_unknown {
            unknown.entry(key).or_insert(value);
        }
    }
    input_pairs.shuffle(rng);
    output_pairs.shuffle(rng);
    let (input, inputs) = input_pairs.into_iter().unzip();
    let (output, outputs) = output_pairs.into_iter().unzip();
    Ok(Psbt {
        unsigned_tx: Transaction {
            version: Version(i32::from_le_bytes(version.to_le_bytes())),
            lock_time: LockTime::from_consensus(locktime),
            input,
            output,
        },
        version: 0,
        // Core's final shuffled object retains only global unknowns. Its
        // temporary xpub merge and global proprietary data do not survive.
        xpub: BTreeMap::new(),
        proprietary: BTreeMap::new(),
        unknown,
        inputs,
        outputs,
    })
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "fixtures and observed contracts name failures"
)]
mod tests {
    use super::*;
    use bitcoin::psbt::raw::Key;
    use bitcoin::secp256k1::rand::{SeedableRng as _, rngs::StdRng};
    use bitcoin::{Amount, ScriptBuf, TxOut};
    use sonic_rs::json;

    fn fixtures() -> serde_json::Value {
        serde_json::from_str(include_str!("../../tests/fixtures/joinpsbts.json"))
            .expect("reference fixtures")
    }

    fn source(name: &str) -> Psbt {
        crate::psbt::decode(fixtures()["psbts"][name].as_str().expect("named PSBT"))
            .expect("strict source")
    }

    fn join(sources: Vec<Psbt>) -> Psbt {
        assemble_join(sources, &mut StdRng::seed_from_u64(1487)).expect("join")
    }

    #[test]
    fn join_preserves_paired_metadata_and_observed_core_global_rules() {
        let first = source("metadata-a");
        let second = source("metadata-b");
        assert!(!first.xpub.is_empty());
        assert!(!first.proprietary.is_empty());
        let first_input = first.unsigned_tx.input[0].clone();
        let mut expected_map = first.inputs[0].clone();
        expected_map.partial_sigs.clear();
        expected_map.final_script_sig = None;
        expected_map.final_script_witness = None;
        let expected_output_map = first.outputs[0].clone();
        let result = join(vec![first, second]);
        assert!(result.xpub.is_empty() && result.proprietary.is_empty());
        assert_eq!(
            result.unknown[&Key {
                type_value: 0xfa,
                key: vec![1]
            }],
            b"first"
        );
        let index = result
            .unsigned_tx
            .input
            .iter()
            .position(|input| *input == first_input)
            .expect("retained input");
        assert_eq!(result.inputs[index], expected_map);
        assert!(result.inputs[index].tap_key_sig.is_some());
        assert!(!result.inputs[index].tap_script_sigs.is_empty());
        assert!(result.outputs.contains(&expected_output_map));
        assert_eq!(
            result
                .outputs
                .iter()
                .filter(|map| !map.proprietary.is_empty())
                .count(),
            1
        );
        let reversed = join(vec![source("metadata-b"), source("metadata-a")]);
        assert_eq!(
            reversed.unknown[&Key {
                type_value: 0xfa,
                key: vec![1]
            }],
            b"second"
        );
    }

    #[test]
    fn duplicate_identity_includes_sequence_and_versions_are_unsigned() {
        for version in [0_u32, 1, 2, 3, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            let result = join(vec![source("a"), source(&format!("version-{version}"))]);
            assert_eq!(
                u32::from_le_bytes(result.unsigned_tx.version.0.to_le_bytes()),
                version.max(1)
            );
            assert_eq!(result.unsigned_tx.lock_time.to_consensus_u32(), 500);
        }
        let result = join(vec![source("a"), source("same-prevout-new-sequence")]);
        assert_eq!(result.unsigned_tx.input.len(), 2);
        for sources in [
            vec![source("a"), source("a")],
            vec![source("duplicate-inside"), source("b")],
        ] {
            let error = assemble_join(sources, &mut StdRng::seed_from_u64(0))
                .expect_err("duplicate refused");
            assert_eq!(error.code(), -8);
            assert!(error.to_string().contains("exists in multiple PSBTs"));
        }
        let result = join(vec![
            source("zero-version-zero-lock"),
            source("zero-version-other"),
        ]);
        assert_eq!(result.unsigned_tx.version, Version::ONE);
        assert_eq!(result.unsigned_tx.lock_time, LockTime::ZERO);
        let empty = join(vec![source("empty"), source("empty")]);
        assert!(empty.inputs.is_empty() && empty.outputs.is_empty());
    }

    fn blank(outputs: usize) -> Psbt {
        Psbt::from_unsigned_tx(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![
                TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: ScriptBuf::new()
                };
                outputs
            ],
        })
        .expect("blank unsigned PSBT")
    }

    fn call(sources: &[String]) -> Result<Value, RpcError> {
        joinpsbts(&Arc::new(Context::new()), &json!([sources]))
    }

    #[test]
    fn aggregate_source_item_map_and_byte_limits_are_enforced() {
        let empty = crate::psbt::encode(&blank(0)).expect("empty encoding");
        assert!(call(&vec![empty.clone(); 256]).is_ok());
        assert_eq!(
            call(&vec![empty; 257]).expect_err("source bound").code(),
            -8
        );
        let half = crate::psbt::encode(&blank(5_000)).expect("within individual item bound");
        assert!(call(&[half.clone(), half.clone()]).is_ok());
        let over = crate::psbt::encode(&blank(5_001)).expect("individually bounded");
        assert_eq!(
            call(&[half, over])
                .expect_err("aggregate item bound")
                .code(),
            -8
        );
        let mut mapped = blank(0);
        for index in 0_u32..50_000 {
            mapped.unknown.insert(
                Key {
                    type_value: 0xfa,
                    key: index.to_le_bytes().to_vec(),
                },
                vec![1],
            );
        }
        let encoded = crate::psbt::encode(&mapped).expect("within individual map bound");
        assert_eq!(
            call(&[encoded.clone(), encoded])
                .expect_err("aggregate map bound")
                .code(),
            -8
        );
        // Neither source is decoded when their combined wire bytes exceed
        // admission: malformed magic would otherwise produce -22.
        let large = "AAAA".repeat(4_194_304);
        assert_eq!(
            call(&[large, "AAAA".into()])
                .expect_err("aggregate byte bound")
                .code(),
            -8
        );
    }

    #[test]
    fn type_decode_and_duplicate_error_order_matches_core() {
        let ctx = Arc::new(Context::new());
        assert_eq!(
            joinpsbts(&ctx, &json!([[1]]))
                .expect_err("cardinality first")
                .code(),
            -8
        );
        assert_eq!(
            joinpsbts(&ctx, &json!([["!", 1]]))
                .expect_err("decode first source")
                .code(),
            -22
        );
        let duplicate = fixtures()["psbts"]["duplicate-inside"]
            .as_str()
            .expect("source")
            .to_owned();
        assert_eq!(
            call(&[duplicate, "!".into()])
                .expect_err("decode before duplicate")
                .code(),
            -22
        );
    }
}
