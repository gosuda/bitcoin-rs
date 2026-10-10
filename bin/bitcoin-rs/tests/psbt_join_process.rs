//! Public joinpsbts comparisons against the checksum-pinned Core process.
//! Normalize only shuffle-dependent tx identities, positions and pair order.

use std::collections::BTreeSet;
use std::path::Path;

use bitcoin_rs_e2e::differential::compare_reply;
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, SpawnOptions};
use serde_json::{Value, json};

fn start(kind: Kind) -> Result<ProcessNode> {
    ProcessNode::spawn_with(
        kind,
        &SpawnOptions {
            binary: Some(Path::new(env!("CARGO_BIN_EXE_bitcoin-rs"))),
            ..Default::default()
        },
    )
}

fn fixtures() -> Result<Value> {
    // ProcessNode independently verifies the running Core binary against the
    // repository's release pin; fixture provenance remains in the JSON file.
    serde_json::from_str(include_str!(
        "../../../crates/rpc/tests/fixtures/joinpsbts.json"
    ))
    .map_err(Error::Json)
}

fn fixture<'a>(fixtures: &'a Value, name: &str) -> Result<&'a str> {
    fixtures["psbts"][name]
        .as_str()
        .ok_or_else(|| Error::Protocol(format!("missing {name} fixture")))
}

fn array(value: &Value) -> Result<&Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| Error::Protocol("missing PSBT array".into()))
}

/// Pair every map with its transaction entry before sorting. Equal output
/// values/scripts with different metadata remain distinct multiset entries.
fn normalize(mut decoded: Value) -> Result<Value> {
    for (tx_field, map_field) in [("vin", "inputs"), ("vout", "outputs")] {
        let entries = array(&decoded["tx"][tx_field])?;
        let maps = array(&decoded[map_field])?;
        assert_eq!(entries.len(), maps.len(), "one metadata map per entry");
        let mut pairs = entries
            .iter()
            .zip(maps)
            .map(|(entry, map)| {
                let mut entry = entry.clone();
                if tx_field == "vout" {
                    if let Some(object) = entry.as_object_mut() {
                        object.remove("n");
                    }
                }
                json!([entry, map])
            })
            .collect::<Vec<_>>();
        pairs.sort_by_cached_key(Value::to_string);
        decoded["tx"][tx_field] = json!(pairs);
        if let Some(object) = decoded.as_object_mut() {
            object.remove(map_field);
        }
    }
    let tx = decoded["tx"]
        .as_object_mut()
        .ok_or_else(|| Error::Protocol("missing transaction".into()))?;
    tx.remove("txid");
    tx.remove("hash");
    Ok(decoded)
}

fn reference_decode(core: &mut ProcessNode, encoded: &Value) -> Result<Value> {
    core.rpc("decodepsbt", &json!([encoded]))
}

fn compare_join(
    core: &mut ProcessNode,
    node: &mut ProcessNode,
    name: &str,
    params: &Value,
) -> Result<Value> {
    let reference = core.rpc("joinpsbts", params)?;
    let candidate = node.rpc("joinpsbts", params)?;
    // The independent reference parser interprets both wire results, so a
    // candidate-only PSBT projector cannot conceal detached/missing metadata.
    let reference_view = normalize(reference_decode(core, &reference)?)?;
    let candidate_view = normalize(reference_decode(core, &candidate)?)?;
    std::fs::write(
        node.evidence.join(format!("join-{name}.json")),
        serde_json::to_vec_pretty(&json!({
            "params":params, "reference_psbt":reference, "candidate_psbt":candidate,
            "reference_normalized":reference_view, "candidate_normalized":candidate_view,
            "reference_evidence":core.evidence,
        }))?,
    )?;
    compare_reply(name, &reference_view, &candidate_view)?;
    Ok(candidate_view)
}

#[test]
fn join_metadata_duplicate_identity_and_unsigned_versions_match_core() -> Result<()> {
    let f = fixtures()?;
    let a = fixture(&f, "a")?;
    let b = fixture(&f, "b")?;
    let mut core = start(Kind::Core)?;
    let mut node = start(Kind::BitcoinRs)?;
    compare_join(&mut core, &mut node, "basic", &json!([[a, b]]))?;
    compare_join(&mut core, &mut node, "named", &json!({"txs":[a,b]}))?;
    compare_join(&mut core, &mut node, "args", &json!({"args":[[a,b]]}))?;
    compare_join(
        &mut core,
        &mut node,
        "same-prevout-new-sequence",
        &json!([[a, fixture(&f, "same-prevout-new-sequence")?]]),
    )?;
    for version in [0_u32, 1, 2, 3, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
        let name = format!("version-{version}");
        let joined = compare_join(
            &mut core,
            &mut node,
            &name,
            &json!([[a, fixture(&f, &name)?]]),
        )?;
        assert_eq!(joined["tx"]["version"], version.max(1));
        assert_eq!(joined["tx"]["locktime"], 500);
    }
    compare_join(
        &mut core,
        &mut node,
        "floor-and-min",
        &json!([[
            fixture(&f, "zero-version-zero-lock")?,
            fixture(&f, "zero-version-other")?
        ]]),
    )?;
    for (first, second, expected) in [
        ("metadata-a", "metadata-b", "6669727374"),
        ("metadata-b", "metadata-a", "7365636f6e64"),
    ] {
        let joined = compare_join(
            &mut core,
            &mut node,
            first,
            &json!([[fixture(&f, first)?, fixture(&f, second)?]]),
        )?;
        assert_eq!(joined["global_xpubs"], json!([]));
        assert_eq!(joined["proprietary"], json!([]));
        assert_eq!(joined["unknown"]["fa01"], expected);
    }
    compare_join(
        &mut core,
        &mut node,
        "empty",
        &json!([[fixture(&f, "empty")?, fixture(&f, "empty")?]]),
    )?;
    core.stop()?;
    node.stop()?;
    Ok(())
}

fn contains_witness_stack(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            object
                .get("txinwitness")
                .and_then(Value::as_array)
                .is_some_and(|stack| !stack.is_empty())
                || object.values().any(contains_witness_stack)
        }
        Value::Array(values) => values.iter().any(contains_witness_stack),
        _ => false,
    }
}

#[test]
fn join_uses_shared_non_witness_utxo_output_normalization() -> Result<()> {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../crates/rpc/tests/data/psbt-codec-core-v31.1.json"
    ))?;
    let source = array(&corpus["cases"])?
        .iter()
        .find(|case| case["name"] == "core-valid-0")
        .and_then(|case| case["psbt"].as_str())
        .ok_or_else(|| Error::Protocol("missing parent-owned witness fixture".into()))?;
    let f = fixtures()?;
    let mut core = start(Kind::Core)?;
    let mut node = start(Kind::BitcoinRs)?;
    let original = core.rpc("decodepsbt", &json!([source]))?;
    assert!(
        contains_witness_stack(&original),
        "fixture must exercise nested witness stripping"
    );
    let joined = compare_join(
        &mut core,
        &mut node,
        "nested-witness-output-normalization",
        &json!([[source, fixture(&f, "b")?]]),
    )?;
    assert!(!contains_witness_stack(&joined));
    core.stop()?;
    node.stop()?;
    Ok(())
}

#[test]
fn join_preserves_canonical_taproot_signatures_and_refuses_declared_restrictions() -> Result<()> {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../crates/rpc/tests/data/psbt-codec-core-v31.1.json"
    ))?;
    let source = |name: &str| -> Result<&str> {
        array(&corpus["cases"])?
            .iter()
            .find(|case| case["name"] == name)
            .and_then(|case| case["psbt"].as_str())
            .ok_or_else(|| Error::Protocol(format!("missing parent-owned {name} fixture")))
    };
    let f = fixtures()?;
    let mut core = start(Kind::Core)?;
    let mut node = start(Kind::BitcoinRs)?;
    for kind in ["taproot", "tapscript"] {
        for encoding in ["64-control", "65-all"] {
            let name = format!("probe-{kind}-{encoding}");
            compare_join(
                &mut core,
                &mut node,
                &name,
                &json!([[source(&name)?, fixture(&f, "b")?]]),
            )?;
        }
        for (encoding, suffix) in [("65-explicit-default", "00"), ("65-unknown", "04")] {
            let name = format!("probe-{kind}-{encoding}");
            let params = json!([[source(&name)?, fixture(&f, "b")?]]);
            let accepted = core.rpc("joinpsbts", &params)?;
            let decoded = reference_decode(&mut core, &accepted)?;
            let expected_signature = format!("{}{suffix}", "11".repeat(64));
            assert!(array(&decoded["inputs"])?.iter().any(|input| {
                input["taproot_key_path_sig"] == expected_signature
                    || input["taproot_script_path_sigs"]
                        .as_array()
                        .is_some_and(|signatures| {
                            signatures
                                .iter()
                                .any(|signature| signature["sig"] == expected_signature)
                        })
            }));
            let rejected = node.rpc_raw(&json!({
                "jsonrpc":"2.0", "id":1, "method":"joinpsbts", "params":params,
            }))?;
            assert_eq!(rejected["error"]["code"], -22, "{name}");
        }
    }
    core.stop()?;
    node.stop()?;
    Ok(())
}

#[test]
fn join_parameter_decode_and_duplicate_errors_match_core() -> Result<()> {
    let f = fixtures()?;
    let a = fixture(&f, "a")?;
    let b = fixture(&f, "b")?;
    let duplicate = fixture(&f, "duplicate-inside")?;
    let mut core = start(Kind::Core)?;
    let mut node = start(Kind::BitcoinRs)?;
    let params = [
        json!([]),
        json!([null]),
        json!([1]),
        json!([[]]),
        json!([[a]]),
        json!([[1]]),
        json!([[a, 1]]),
        json!([[a, "!"]]),
        json!([["!", 1]]),
        json!([[a, b], 0]),
        json!({"txs":[a,b],"wat":1}),
        json!({"args":[[a,b]],"txs":[a,b]}),
        json!([[a, a]]),
        json!([[a, fixture(&f, "same-prevout-same-sequence")?]]),
        json!([[duplicate, b]]),
        json!([[duplicate, "!"]]),
    ];
    for (index, params) in params.into_iter().enumerate() {
        let request =
            json!({"jsonrpc":"2.0","id":"join-error","method":"joinpsbts","params":params});
        let expected = core.rpc_raw(&request)?;
        let actual = node.rpc_raw(&request)?;
        compare_reply(&format!("join error {index}"), &expected, &actual)?;
    }
    core.stop()?;
    node.stop()?;
    Ok(())
}

fn input_order(decoded: &Value) -> Result<Vec<u64>> {
    array(&decoded["tx"]["vin"])?
        .iter()
        .map(|input| {
            input["sequence"]
                .as_u64()
                .ok_or_else(|| Error::Protocol("sequence".into()))
        })
        .collect()
}

fn output_order(decoded: &Value) -> Result<Vec<String>> {
    array(&decoded["tx"]["vout"])?
        .iter()
        .map(|output| {
            output["scriptPubKey"]["hex"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error::Protocol("script hex".into()))
        })
        .collect()
}

#[test]
fn join_actually_shuffles_both_paired_collections() -> Result<()> {
    let f = fixtures()?;
    let params = json!([[
        fixture(&f, "a")?,
        fixture(&f, "b")?,
        fixture(&f, "same-prevout-new-sequence")?
    ]]);
    let mut core = start(Kind::Core)?;
    let mut node = start(Kind::BitcoinRs)?;
    let baseline = compare_join(&mut core, &mut node, "shuffle-baseline", &params)?;
    let mut inputs = BTreeSet::new();
    let mut outputs = BTreeSet::new();
    let mut independent = false;
    for _ in 0..32 {
        let result = node.rpc("joinpsbts", &params)?;
        let decoded = reference_decode(&mut core, &result)?;
        let input_order = input_order(&decoded)?;
        let output_order = output_order(&decoded)?;
        let corresponding = input_order
            .iter()
            .map(|sequence| match sequence {
                100 => "51",
                200 => "52",
                101 => "53",
                _ => "unexpected",
            })
            .collect::<Vec<_>>();
        independent |= corresponding != output_order;
        inputs.insert(input_order);
        outputs.insert(output_order);
        compare_reply(
            "all shuffled maps stay attached",
            &baseline,
            &normalize(decoded)?,
        )?;
    }
    // Each side has three distinct entries. Repeated calls must vary both
    // orders and must not reuse one shared permutation; no fixed order is required.
    assert!(inputs.len() > 1 && outputs.len() > 1 && independent);
    core.stop()?;
    node.stop()?;
    Ok(())
}
