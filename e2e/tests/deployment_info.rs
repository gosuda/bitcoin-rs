//! Deployment transport and declared native differences against pinned Core.

use bitcoin_rs_e2e::differential::{compare_reply, mine_common_chain};
use bitcoin_rs_e2e::{Kind, ProcessNode, Result, SpawnOptions};
use serde_json::json;

#[test]
fn deployment_info_historical_rpc_rest_and_native_deviations() -> Result<()> {
    let mut core = ProcessNode::spawn_with(
        Kind::Core,
        &SpawnOptions {
            extra_args: &["-rest=1"],
            ..SpawnOptions::default()
        },
    )?;
    let mut node = ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            extra_args: &["--rest=true"],
            ..SpawnOptions::default()
        },
    )?;
    for _ in 0..5 {
        mine_common_chain(&mut core, &mut node, 100)?;
    }
    for height in [0, 1, 2, 430, 431, 432, 498, 499, 500] {
        let hash = core.rpc("getblockhash", &json!([height]))?;
        let reference = core.rpc("getdeploymentinfo", &json!([hash]))?;
        let native = node.rpc("getdeploymentinfo", &json!([hash]))?;
        assert_eq!(native["hash"], reference["hash"]);
        assert_eq!(native["height"], reference["height"]);
        assert_eq!(native["deployments"]["bip34"]["height"], 500);
        assert_eq!(reference["deployments"]["bip34"]["height"], 1);
        assert_eq!(native["deployments"]["csv"]["active"], height >= 431);
        assert_eq!(native["deployments"]["bip34"]["active"], height >= 499);
        assert_eq!(reference["deployments"]["csv"]["active"], true);
        assert_eq!(native["deployments"]["taproot"]["type"], "buried");
        assert_eq!(reference["deployments"]["taproot"]["type"], "bip9");
        assert!(native["deployments"].get("testdummy").is_none());
        assert!(reference["deployments"].get("testdummy").is_some());
        let expected_flags = if height >= 432 {
            json!([
                "CHECKSEQUENCEVERIFY",
                "NULLDUMMY",
                "P2SH",
                "TAPROOT",
                "WITNESS"
            ])
        } else {
            json!(["NULLDUMMY", "P2SH", "TAPROOT", "WITNESS"])
        };
        assert_eq!(native["script_flags"], expected_flags);
        for process in [&mut core, &mut node] {
            let rpc = process.rpc("getdeploymentinfo", &json!({"blockhash": hash}))?;
            let text = hash
                .as_str()
                .ok_or_else(|| bitcoin_rs_e2e::Error::Assertion("hash was not string".into()))?;
            compare_reply(
                "args prefix",
                &rpc,
                &process.rpc("getdeploymentinfo", &json!({"args": [hash]}))?,
            )?;
            let rest = process.http_get(&format!("/rest/deploymentinfo/{text}.json"))?;
            assert_eq!(rest.status, 200);
            compare_reply("explicit historical RPC/REST", &rpc, &rest.json()?)?;
            assert!(!serde_json::to_string(&rpc)?.contains("null"));
        }
    }
    for process in [&mut core, &mut node] {
        let rpc = process.rpc("getdeploymentinfo", &json!([]))?;
        compare_reply(
            "default RPC/REST",
            &rpc,
            &process.http_get("/rest/deploymentinfo.json")?.json()?,
        )?;
        compare_reply(
            "null default",
            &rpc,
            &process.rpc("getdeploymentinfo", &json!([null]))?,
        )?;
    }
    check_errors(&mut core, &mut node)?;
    node.stop()?;
    core.stop()
}

fn check_errors(core: &mut ProcessNode, node: &mut ProcessNode) -> Result<()> {
    for params in [
        json!(["bad"]),
        json!(["00".repeat(32)]),
        json!([4]),
        json!({"wrong": 1}),
        json!({"args": [null], "blockhash": null}),
    ] {
        let request =
            json!({"jsonrpc": "2.0", "id": 1, "method": "getdeploymentinfo", "params": params});
        let reference = core.rpc_raw(&request)?;
        let native = node.rpc_raw(&request)?;
        compare_reply(
            "deployment parameter error",
            &reference["error"],
            &native["error"],
        )?;
    }
    for path in [
        "/rest/deploymentinfo/bad.json".to_owned(),
        format!("/rest/deploymentinfo/{}.json", "00".repeat(32)),
        "/rest/deploymentinfo.bin".to_owned(),
    ] {
        let reference = core.http_get(&path)?;
        let native = node.http_get(&path)?;
        assert_eq!(reference.status, native.status);
    }
    Ok(())
}
