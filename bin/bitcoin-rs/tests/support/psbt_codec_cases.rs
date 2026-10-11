//! Shared PSBT foundation: actual Core codec behavior and existing RPC boundaries.
use super::start;
use bitcoin_rs_e2e::{Error, Kind};
use serde_json::{Value, json};

#[test]
fn shared_psbt_codec_follows_core_and_retains_legacy_error_classes() {
    let mut core = start(Kind::Core);
    let mut node = start(Kind::BitcoinRs);
    let data: Value = serde_json::from_str(include_str!(
        "../../../../crates/rpc/tests/data/psbt-codec-core-v31.1.json"
    ))
    .expect("independent fixtures");
    let mut differences = Vec::new();
    for case in data["cases"].as_array().expect("cases") {
        let name = case["name"].as_str().expect("name");
        let encoded = &case["psbt"];
        let expected = case["core_valid"].as_bool().expect("expectation");
        let reference = core.rpc("combinepsbt", &json!([[encoded]]));
        let candidate = node.rpc("combinepsbt", &json!([[encoded]]));
        if expected && case["candidate_valid"] == false {
            assert!(
                reference.is_ok(),
                "{name}: Core accepts supplied metadata encoding"
            );
            assert!(
                matches!(candidate, Err(Error::Rpc { code: -32602, .. })),
                "{name}: declared typed-field rejection"
            );
            continue;
        }
        if expected {
            match (reference, candidate) {
                (Ok(reference), Ok(candidate)) => {
                    if case["exact_roundtrip"] == true {
                        assert_eq!(
                            candidate, reference,
                            "{name}: exact optional-field omission"
                        );
                    }
                    let reference = core
                        .rpc("decodepsbt", &json!([reference]))
                        .expect("Core encoded result");
                    let mut candidate = core
                        .rpc("decodepsbt", &json!([candidate]))
                        .expect("candidate encoded result");
                    if name == "core-valid-18" {
                        assert_taptree_orientation_only(&mut core, &reference, &mut candidate);
                    }
                    if reference != candidate {
                        differences.push(format!("{name}: metadata difference: reference={reference};candidate={candidate}"));
                    }
                }
                (reference, candidate) => differences.push(format!(
                    "{name}: expected accepted: reference={reference:?};candidate={candidate:?}"
                )),
            }
        } else {
            if !matches!(reference, Err(Error::Rpc { code: -22, .. }))
                || !matches!(candidate, Err(Error::Rpc { code: -32602, .. }))
            {
                differences.push(format!(
                    "{name}: rejection boundary: reference={reference:?};candidate={candidate:?}"
                ));
            }
            let finalized = node.rpc("finalizepsbt", &json!([encoded]));
            if !matches!(finalized, Err(Error::Rpc { code: -32602, .. })) {
                differences.push(format!("{name}: finalize boundary: {finalized:?}"));
            }
        }
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}

#[test]
fn combined_xpub_aliases_follow_core_and_refuse_unreadable_origins() {
    let mut core = start(Kind::Core);
    let mut node = start(Kind::BitcoinRs);
    let data: Value = serde_json::from_str(include_str!(
        "../../../../crates/rpc/tests/data/psbt-combine-core-v31.1.json"
    ))
    .expect("independent combine fixtures");
    for case in data["cases"].as_array().expect("combine cases") {
        let name = case["name"].as_str().expect("name");
        for source in case["sources"].as_array().expect("source PSBTs") {
            core.rpc("decodepsbt", &json!([source]))
                .expect("each source is independently valid");
        }
        let params = json!([case["sources"]]);
        let reference = core.rpc("combinepsbt", &params).expect("Core combination");
        assert_eq!(
            reference, case["core_result"],
            "{name}: recorded Core output"
        );
        let readable = core.rpc("decodepsbt", &json!([reference]));
        let candidate = node.rpc("combinepsbt", &params);
        if case["core_output_valid"] == true {
            assert!(readable.is_ok(), "{name}: Core output is readable");
        } else {
            let expected = case["core_output_error"]["message"]
                .as_str()
                .expect("Core error");
            assert!(
                matches!(readable, Err(Error::Rpc { code: -22, message, .. }) if message == expected),
                "{name}: Core output is unreadable"
            );
        }
        if case["candidate_result"].is_string() {
            let result = candidate.expect("readable combination");
            assert_eq!(
                result, case["candidate_result"],
                "{name}: retained metadata"
            );
            core.rpc("decodepsbt", &json!([result]))
                .expect("candidate output remains readable");
        } else {
            let expected = case
                .get("candidate_error")
                .unwrap_or_else(|| &case["core_output_error"]);
            assert!(
                matches!(candidate, Err(Error::Rpc { code, message, .. }) if Some(code) == expected["code"].as_i64() && Some(message.as_str()) == expected["message"].as_str()),
                "{name}: preserve the refusal class and library-error precedence"
            );
        }
    }
}

// The typed library canonically orders these sibling nodes. Preserve one typed
// tree owner; prove the exact observed reorder commits to the same output using
// independent Core descriptor derivation before comparing every other field.
fn assert_taptree_orientation_only(
    core: &mut bitcoin_rs_e2e::ProcessNode,
    reference: &Value,
    candidate: &mut Value,
) {
    let expected = &reference["outputs"][0]["taproot_tree"];
    let actual = &candidate["outputs"][0]["taproot_tree"];
    assert_eq!(actual[0], expected[1]);
    assert_eq!(actual[1], expected[0]);
    assert_eq!(actual[2], expected[2]);
    let mut addresses = Vec::new();
    for tree in [expected, actual] {
        let rows = tree.as_array().expect("three leaves");
        assert_eq!(rows.len(), 3);
        assert_eq!(
            [
                rows[0]["depth"].as_u64(),
                rows[1]["depth"].as_u64(),
                rows[2]["depth"].as_u64()
            ],
            [Some(2), Some(2), Some(1)]
        );
        let keys: Vec<_> = rows
            .iter()
            .map(|row| {
                let script = row["script"].as_str().expect("script");
                assert_eq!(script.len(), 68);
                assert!(script.starts_with("20") && script.ends_with("ac"));
                &script[2..66]
            })
            .collect();
        let internal = reference["outputs"][0]["taproot_internal_key"]
            .as_str()
            .expect("internal key");
        let descriptor = format!(
            "tr({internal},{{{{pk({}),pk({})}},pk({})}})",
            keys[0], keys[1], keys[2]
        );
        let info = core
            .rpc("getdescriptorinfo", &json!([descriptor]))
            .expect("Core descriptor");
        let derived = core
            .rpc("deriveaddresses", &json!([info["descriptor"]]))
            .expect("Core commitment address");
        addresses.push(derived[0].clone());
    }
    assert_eq!(
        addresses[0], addresses[1],
        "sibling orientation preserves the commitment"
    );
    assert_eq!(
        addresses[0],
        reference["tx"]["vout"][0]["scriptPubKey"]["address"]
    );
    candidate["outputs"][0]["taproot_tree"] = expected.clone();
}
