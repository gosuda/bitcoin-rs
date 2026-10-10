//! Actual unmodified Core and native daemon block-validation comparisons.
#[path = "../../../../crates/script/tests/support/taproot_spends.rs"]
mod fixture;

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin_rs_e2e::{Kind, SpawnOptions};
use serde_json::json;

#[test]
fn native_taproot_spend_rules_match_pinned_core() {
    compare_cases(
        &fixture::funding_script(),
        fixture::cases,
        "taproot-spend-rules.json",
    );
}

#[test]
fn native_taproot_op_success_matches_pinned_core() {
    compare_cases(
        &fixture::success_funding_script(),
        fixture::success_cases,
        "taproot-op-success.json",
    );
}

fn compare_cases(
    script: &bitcoin::Script,
    cases: fn(bitcoin::OutPoint, &bitcoin::TxOut) -> Vec<fixture::Case>,
    artifact: &str,
) {
    let mut core = super::start(Kind::Core);
    let mut node = bitcoin_rs_e2e::ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            binary: Some(super::self_binary()),
            extra_args: &["--validation-engine=native"],
            ..Default::default()
        },
    )
    .expect("native daemon");
    let address =
        bitcoin::Address::from_script(script, bitcoin::Network::Regtest).expect("Taproot address");
    let hashes = core
        .rpc("generatetoaddress", &json!([101, address.to_string()]))
        .expect("isolated coinbase funding");
    for hash in hashes.as_array().expect("hashes") {
        let raw = core
            .rpc("getblock", &json!([hash, 0]))
            .expect("Core block bytes");
        assert!(
            node.rpc("submitblock", &json!([raw]))
                .expect("same block bytes")
                .is_null()
        );
    }
    let raw = core
        .rpc("getblock", &json!([hashes[0], 0]))
        .expect("funding block");
    let block: bitcoin::Block =
        deserialize_hex(raw.as_str().expect("hex")).expect("reference decode");
    let coinbase = &block.txdata[0];
    let prevout = coinbase.output[0].clone();
    assert_eq!(prevout.script_pubkey.as_script(), script);
    let outpoint = bitcoin::OutPoint::new(coinbase.compute_txid(), 0);
    let mut differences = Vec::new();
    let mut evidence = Vec::new();
    for case in cases(outpoint, &prevout) {
        let params = json!(["raw(51)", [serialize_hex(&case.tx)], false]);
        // Proposal validation accepts consensus-valid annexes without conflating
        // Core's mempool policy restrictions with its script verifier.
        let reference = core.rpc("generateblock", &params);
        let candidate = node.rpc("generateblock", &params);
        evidence.push(json!({"name":case.name,"tx":serialize_hex(&case.tx),"expected":case.accepted,"core":format!("{reference:?}"),"candidate":format!("{candidate:?}")}));
        if reference.is_ok() != case.accepted {
            differences.push(format!(
                "{}: reference disagrees with BIP341 expectation: {reference:?}",
                case.name
            ));
        }
        if candidate.is_ok() != reference.is_ok() {
            differences.push(format!(
                "{}: Core={reference:?};native={candidate:?}",
                case.name
            ));
        }
    }
    assert_eq!(
        core.rpc("getblockcount", &json!([]))
            .expect("Core unchanged"),
        json!(101)
    );
    assert_eq!(
        node.rpc("getblockcount", &json!([]))
            .expect("native unchanged"),
        json!(101)
    );
    std::fs::write(
        node.evidence.join(artifact),
        serde_json::to_vec_pretty(&evidence).expect("evidence JSON"),
    )
    .expect("evidence");
    core.stop().expect("Core stop");
    node.stop().expect("native stop");
    assert!(
        differences.is_empty(),
        "Taproot mismatches:\n{}",
        differences.join("\n")
    );
}
