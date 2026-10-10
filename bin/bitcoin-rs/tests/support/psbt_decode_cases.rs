//! Core31.1 public metadata projection, using the shared typed codec fixtures.
use super::start;
use bitcoin_rs_e2e::{Error, Kind};
use serde_json::{Value, json};

#[test]
fn decoded_psbt_metadata_matches_core() {
    let mut core = start(Kind::Core);
    let mut node = start(Kind::BitcoinRs);
    let mut differences = Vec::new();
    for source in [
        include_str!("../../../../crates/rpc/tests/data/psbt-codec-core-v31.1.json"),
        include_str!("../../../../crates/rpc/tests/data/psbt-decode-core-v31.1.json"),
    ] {
        let data: Value = serde_json::from_str(source).expect("independent vectors");
        for case in data["cases"].as_array().expect("cases") {
            let name = case["name"].as_str().expect("name");
            let params = json!([case["psbt"]]);
            let reference = core.rpc("decodepsbt", &params);
            let candidate = node.rpc("decodepsbt", &params);
            if case["candidate_valid"] == false {
                assert!(reference.is_ok(), "{name}: measured Core acceptance");
                assert!(
                    matches!(candidate, Err(Error::Rpc { code: -22, .. })),
                    "{name}: declared typed restriction: {candidate:?}"
                );
                continue;
            }
            match (reference, candidate) {
                (Ok(reference), Ok(mut candidate)) => {
                    if name == "core-valid-18" {
                        super::psbt_codec_cases::assert_taptree_orientation_only(
                            &mut core,
                            &reference,
                            &mut candidate,
                        );
                    }
                    if reference != candidate {
                        differences.push(format!(
                            "{name}: reference={reference}; candidate={candidate}"
                        ));
                    }
                }
                (
                    Err(Error::Rpc {
                        code: -22,
                        message: reference,
                        ..
                    }),
                    Err(Error::Rpc {
                        code: -22,
                        message: candidate,
                        ..
                    }),
                ) => {
                    if matches!(
                        name,
                        "wrong-nonwitness-hash"
                            | "wrong-nonwitness-index"
                            | "trailing-data"
                            | "invalid-base64"
                            | "global-truncated-keytype"
                            | "truncated-subtype"
                    ) {
                        assert_eq!(candidate, reference, "{name}: adapted diagnostic");
                    }
                }
                (reference, candidate) => differences.push(format!(
                    "{name}: reference={reference:?}; candidate={candidate:?}"
                )),
            }
        }
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}

#[test]
fn decodepsbt_parameter_forms_follow_core() {
    let mut core = start(Kind::Core);
    let mut node = start(Kind::BitcoinRs);
    let data: Value = serde_json::from_str(include_str!(
        "../../../../crates/rpc/tests/data/psbt-codec-core-v31.1.json"
    ))
    .expect("fixtures");
    let encoded = &data["cases"][0]["psbt"];
    for params in [
        json!([encoded]),
        json!({"psbt":encoded}),
        json!({"args":[encoded]}),
        json!([]),
        json!({}),
        json!([null]),
        json!({"psbt":null}),
        json!([false]),
        json!([42]),
        json!([""]),
        json!(["not base64"]),
        json!([encoded, 0]),
        json!({"psbt":encoded,"extra":1}),
    ] {
        let reference = core.rpc("decodepsbt", &params);
        let candidate = node.rpc("decodepsbt", &params);
        match (reference, candidate) {
            (Ok(reference), Ok(candidate)) => assert_eq!(candidate, reference, "{params}"),
            (Err(Error::Rpc { code: -1, .. }), Err(Error::Rpc { code: -1, .. })) => {}
            (
                Err(Error::Rpc {
                    code: a,
                    message: am,
                    ..
                }),
                Err(Error::Rpc {
                    code: b,
                    message: bm,
                    ..
                }),
            ) => assert_eq!((b, bm), (a, am), "{params}"),
            (reference, candidate) => {
                panic!("{params}: reference={reference:?}; candidate={candidate:?}")
            }
        }
    }
}

#[test]
fn decodepsbt_uses_selected_network_for_nested_transaction_scripts() {
    let data: Value = serde_json::from_str(include_str!(
        "../../../../crates/rpc/tests/data/psbt-codec-core-v31.1.json"
    ))
    .expect("fixtures");
    let encoded = &data["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["name"] == "core-valid-0")
        .expect("nested UTXO")["psbt"];
    for (core_chain, network) in [("main", "mainnet"), ("test", "testnet3")] {
        let chain = format!("-chain={core_chain}");
        let mut core = bitcoin_rs_e2e::ProcessNode::spawn_with(
            Kind::Core,
            &bitcoin_rs_e2e::SpawnOptions {
                extra_args: &["-regtest=0", &chain],
                ..Default::default()
            },
        )
        .expect("isolated reference network");
        let config = format!(
            "network = \"{network}\"\np2p_listen = [\"127.0.0.1:0\"]\ndns_seeds_enabled = false\n"
        );
        let mut node = bitcoin_rs_e2e::ProcessNode::spawn_with(
            Kind::BitcoinRs,
            &bitcoin_rs_e2e::SpawnOptions {
                binary: Some(super::self_binary()),
                toml_override: Some(&config),
                ..Default::default()
            },
        )
        .expect("isolated candidate network");
        bitcoin_rs_e2e::differential::compare_rpc(
            &mut core,
            &mut node,
            "decodepsbt",
            &json!([encoded]),
        )
        .expect("network-aware nested projection");
    }
}
