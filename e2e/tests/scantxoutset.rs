//! Public-process scan comparisons against pinned, unmodified Core 31.1.

use bitcoin_rs_e2e::differential::{compare_reply, compare_rpc};
use bitcoin_rs_e2e::helpers::submit_genesis;
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, ValueExt};
use serde_json::{Value, json};

fn compare_scan(
    core: &mut ProcessNode,
    node: &mut ProcessNode,
    name: &str,
    params: Value,
) -> Result<()> {
    let mut request = json!({"jsonrpc":"2.0", "id":"scan", "method":"scantxoutset"});
    request["params"] = params;
    let reference = core.rpc_raw(&request)?;
    let candidate = node.rpc_raw(&request)?;
    std::fs::write(
        node.evidence.join(format!("scan-{name}.json")),
        serde_json::to_vec_pretty(&json!({
            "request":request, "reference":reference, "candidate":candidate,
            "reference_evidence":core.evidence, "candidate_evidence":node.evidence,
        }))?,
    )?;
    compare_reply(name, &reference, &candidate)
}

#[test]
fn fixed_descriptors_scan_identical_core_created_coins() -> Result<()> {
    let mut core = ProcessNode::spawn(Kind::Core)?;
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    compare_scan(&mut core, &mut node, "empty-genesis", json!(["start", []]))?;
    let key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let pkh = format!("pkh({key})");
    let checked = core
        .rpc("getdescriptorinfo", &json!([pkh]))?
        .str_field("descriptor")?
        .to_owned();
    let address = core.rpc("deriveaddresses", &json!([checked]))?[0]
        .as_str()
        .ok_or_else(|| Error::Protocol("Core address missing".into()))?
        .to_owned();
    let descs = vec![
        format!("addr({address})"),
        "raw(51)".into(),
        format!("pkh([deadbeef/1h/2]{key})"),
        format!("wpkh({key})"),
        format!("sh(wpkh({key}))"),
        format!("tr({key})"),
        format!("tr({})", &key[2..]),
        "wpkh([deadbeef/1h/2]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/0/7)".into(),
    ];
    for descriptor in &descs {
        let generated = core.rpc("generateblock", &json!([descriptor, []]))?;
        let hash = generated.str_field("hash")?;
        let block = core.rpc("getblock", &json!([hash, 0]))?;
        let result = node.rpc("submitblock", &json!([block]))?;
        if !result.is_null() {
            return Err(Error::Protocol(format!("Core block rejected: {result}")));
        }
    }
    for (index, descriptor) in descs.iter().enumerate() {
        compare_scan(
            &mut core,
            &mut node,
            &format!("fixed-{index}"),
            json!(["start", [descriptor]]),
        )?;
        compare_scan(
            &mut core,
            &mut node,
            &format!("fixed-range-{index}"),
            json!({
                "action":"start", "scanobjects":[{"desc":descriptor,"range":[0,3]}],
            }),
        )?;
    }
    compare_scan(
        &mut core,
        &mut node,
        "all-first-attribution",
        json!(["start", descs]),
    )?;
    compare_scan(
        &mut core,
        &mut node,
        "duplicate-first-attribution",
        json!([
            "start",
            [
                format!("pkh([deadbeef/1h/2]{key})"),
                format!("addr({address})"),
                format!("pkh({key})"),
            ]
        ]),
    )?;
    // Infer raw descriptors from actual independently generated output bytes.
    let reference = core.rpc("scantxoutset", &json!(["start", descs]))?;
    let coins = reference["unspents"]
        .as_array()
        .ok_or_else(|| Error::Protocol("Core scan coins missing".into()))?;
    let raws = coins
        .iter()
        .map(|coin| {
            coin.str_field("scriptPubKey")
                .map(|script| format!("raw({script})"))
        })
        .collect::<Result<Vec<_>>>()?;
    compare_scan(
        &mut core,
        &mut node,
        "raw-inference",
        json!(["start", raws]),
    )?;
    compare_rpc(&mut core, &mut node, "scantxoutset", &json!(["status"]))?;
    compare_rpc(&mut core, &mut node, "scantxoutset", &json!(["abort"]))?;
    let tip = core.rpc("getbestblockhash", &json!([]))?;
    core.rpc("invalidateblock", &json!([tip]))?;
    node.rpc("invalidateblock", &json!([tip]))?;
    compare_scan(
        &mut core,
        &mut node,
        "after-disconnect",
        json!(["start", descs]),
    )?;
    Ok(())
}

#[test]
fn scan_parameter_and_signed_range_errors_match_core() -> Result<()> {
    let mut core = ProcessNode::spawn(Kind::Core)?;
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    for (name, params) in [
        ("wrong-objects", json!(["start", "x"])),
        ("status-wrong-objects", json!(["status", 1])),
        ("wrong-action-type", json!([1])),
        ("wrong-desc-type", json!(["start", [{"desc":1}]])),
        ("missing-objects", json!(["start"])),
        ("invalid-action", json!(["invalid_command"])),
        ("missing-desc", json!(["start", [{}]])),
        ("bad-scan-object", json!(["start", [1]])),
        ("bad-checksum", json!(["start", ["raw(51)#badbadba"]])),
        (
            "negative-range",
            json!(["start", [{"desc":"raw(51)","range":-1}]]),
        ),
        (
            "negative-begin",
            json!(["start", [{"desc":"raw(51)","range":[-1,1]}]]),
        ),
        (
            "inverted-range",
            json!(["start", [{"desc":"raw(51)","range":[2,1]}]]),
        ),
        (
            "large-range-index",
            json!(["start", [{"desc":"raw(51)","range":2_147_483_648u64}]]),
        ),
        (
            "large-range-count",
            json!(["start", [{"desc":"raw(51)","range":[0,1_000_000]}]]),
        ),
    ] {
        compare_scan(&mut core, &mut node, name, params)?;
    }
    for (index, range) in [
        json!(1.5),
        json!(true),
        json!("1"),
        json!([0, -1]),
        json!([-2, -1]),
        json!([-1, -2]),
        json!([0, "1"]),
        json!(9_223_372_036_854_775_808u64),
    ]
    .into_iter()
    .enumerate()
    {
        compare_scan(
            &mut core,
            &mut node,
            &format!("malformed-range-{index}"),
            json!(["start", [{"desc":"raw(51)","range":range}]]),
        )?;
    }
    Ok(())
}
