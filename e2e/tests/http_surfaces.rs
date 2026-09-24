//! HTTP-surface E2E: RPC auth and protocol errors, batch semantics,
//! REST toggle, the unauthenticated Esplora surface, and ZMQ gating.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use bitcoin_rs_e2e::helpers::{
    genesis_block, mature_funding, mine_bare_blocks, spend_anyone, submit_genesis, tx_hex,
};
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, SpawnOptions};
use serde_json::json;

/// The JSON-RPC listener requires Basic auth.
#[test]
fn rpc_requires_auth() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;

    let unauth = node.http(
        "POST",
        "/",
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockcount\",\"params\":[]}",
        false,
    )?;
    assert_eq!(unauth.status, 401, "missing auth must be 401");

    let body = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockcount\",\"params\":[]}";
    // A wrong password is likewise a 401; the server must not hand a
    // 403/500 or accept it.
    let bad = node.http_auth("POST", "/", body, Some(("parity", "wrong")))?;
    assert_eq!(bad.status, 401, "wrong password must be 401");

    let resp = node.http("POST", "/", body, true)?;
    assert_eq!(resp.status, 200);
    let parsed = resp.json()?;
    assert_eq!(parsed["result"], json!(0));
    node.stop()
}

/// JSON-RPC protocol errors carry their frozen codes.
#[test]
fn rpc_protocol_error_codes() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;

    let unknown = node.rpc_raw(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "frobnicate", "params": []
    }))?;
    assert_eq!(unknown["error"]["code"], json!(-32601));

    // Registered-but-unimplemented methods answer the same code.
    let unimplemented = node.rpc_raw(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "waitforblock", "params": []
    }))?;
    assert_eq!(unimplemented["error"]["code"], json!(-32601));

    // A JSON parse failure maps to HTTP 500 plus a -32700 body, as in Core.
    let malformed = node.http("POST", "/", b"{not json", true)?;
    assert_eq!(malformed.status, 500);
    let parsed = malformed.json()?;
    assert_eq!(parsed["error"]["code"], json!(-32700));

    let wrong_type = node.rpc_raw(&json!({
        "jsonrpc": "2.0", "id": 3, "method": "getblockhash", "params": ["zero"]
    }))?;
    assert!(
        matches!(wrong_type["error"]["code"].as_i64(), Some(-32602 | -8)),
        "bad param type: {wrong_type}"
    );
    node.stop()
}

/// Batches answer every member; notifications get the spec-compliant 204.
#[test]
fn batch_and_notification() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;

    let batch = node.rpc_raw(&json!([
        {"jsonrpc": "2.0", "id": 1, "method": "getblockcount", "params": []},
        {"jsonrpc": "2.0", "id": 2, "method": "getbestblockhash", "params": []}
    ]))?;
    let items = batch
        .as_array()
        .ok_or_else(|| Error::Assertion("batch reply not array".into()))?;
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|i| i.get("result").is_some()));

    let note = node.http(
        "POST",
        "/",
        b"{\"jsonrpc\":\"2.0\",\"method\":\"getblockcount\",\"params\":[]}",
        true,
    )?;
    assert_eq!(note.status, 204, "notification: {}", note.status);
    assert!(note.body.is_empty(), "notification body: {:?}", note.body);
    node.stop()
}

/// The REST gateway is off by default and opt-in via `--rest`.
#[test]
fn rest_toggle() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let off = node.http_get("/rest/chaininfo.json")?;
    assert_eq!(off.status, 404, "REST must be off by default");

    let mut rested = ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            extra_args: &["--rest=true"],
            ..SpawnOptions::default()
        },
    )?;
    let chaininfo = rested.http_get("/rest/chaininfo.json")?;
    assert_eq!(chaininfo.status, 200, "chaininfo: {}", chaininfo.status);
    let info = chaininfo.json()?;
    assert_eq!(info["chain"], json!("regtest"));

    submit_genesis(&mut rested)?;
    let genesis = genesis_block().block_hash().to_string();
    let block = rested.http_get(&format!("/rest/block/{genesis}.json"))?;
    assert_eq!(block.status, 200, "block route: {}", block.status);
    assert_eq!(block.json()?["hash"], json!(genesis));

    let mempool = rested.http_get("/rest/mempool/info.json")?;
    assert_eq!(mempool.status, 200);

    rested.stop()?;
    node.stop()
}

/// The Esplora-compatible `/api` surface answers without auth.
#[test]
fn esplora_public_surface() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let hashes = mine_bare_blocks(&mut node, 4)?;

    let height = node.http_get("/api/blocks/tip/height")?;
    assert_eq!(height.status, 200);
    assert_eq!(height.text()?, "4");

    let tip_hash = node.http_get("/api/blocks/tip/hash")?;
    assert_eq!(tip_hash.text()?, hashes[3]);

    let at_height = node.http_get("/api/block-height/2")?;
    assert_eq!(at_height.status, 200);
    assert_eq!(at_height.text()?, hashes[1]);

    let block = node.http_get(&format!("/api/block/{}", hashes[1]))?;
    assert_eq!(block.status, 200);
    let block_json = block.json()?;
    assert_eq!(block_json["id"], json!(hashes[1]));
    assert_eq!(block_json["height"], json!(2));

    let mempool = node.http_get("/api/mempool")?;
    assert_eq!(mempool.status, 200);
    let mp = mempool.json()?;
    for field in ["count", "vsize", "total_fee", "fee_histogram"] {
        assert!(mp.get(field).is_some(), "mempool lacks {field}: {mp}");
    }

    let blocks = node.http_get("/api/blocks")?;
    assert_eq!(blocks.status, 200);
    let recent = blocks.json()?;
    assert!(
        recent.as_array().is_some_and(|a| !a.is_empty()),
        "recent blocks list: {recent}"
    );

    let fees = node.http_get("/api/fee-estimates")?;
    assert_eq!(fees.status, 200);
    node.stop()
}

/// Esplora `POST /tx` broadcasts a raw transaction into the mempool.
#[test]
fn esplora_post_tx_broadcasts() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let (outpoint, prevout) = mature_funding(&mut node)?;

    let spend = spend_anyone(outpoint, &prevout, 1_000);
    let txid = spend.compute_txid().to_string();
    let resp = node.http("POST", "/api/tx", tx_hex(&spend).as_bytes(), false)?;
    assert_eq!(resp.status, 200, "esplora broadcast: {}", resp.status);
    assert_eq!(resp.text()?, txid);

    bitcoin_rs_e2e::helpers::wait_for_mempool_tx(
        &mut node,
        &txid,
        std::time::Duration::from_secs(15),
    )?;

    // Without txindex the full projection cannot resolve the spend's
    // confirmed prevout, so the capability contract answers 503 rather
    // than an empty success.
    let fetched = node.http_get(&format!("/api/tx/{txid}"))?;
    assert_eq!(fetched.status, 503, "no txindex -> 503: {}", fetched.status);
    node.stop()
}

/// With `--txindex` the full `/api/tx` projection resolves prevouts and
/// confirmation status for a broadcast mempool transaction.
#[test]
fn esplora_tx_projection_with_txindex() -> Result<()> {
    let mut node = ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            extra_args: &["--txindex=true"],
            ..SpawnOptions::default()
        },
    )?;
    let (outpoint, prevout) = mature_funding(&mut node)?;

    let spend = spend_anyone(outpoint, &prevout, 1_000);
    let txid = spend.compute_txid().to_string();
    let resp = node.http("POST", "/api/tx", tx_hex(&spend).as_bytes(), false)?;
    assert_eq!(resp.status, 200, "esplora broadcast: {}", resp.status);
    assert_eq!(resp.text()?, txid);

    bitcoin_rs_e2e::helpers::wait_for_mempool_tx(
        &mut node,
        &txid,
        std::time::Duration::from_secs(15),
    )?;

    // Esplora answers 503 ("index changed during query; retry") while the
    // transaction index crosses a snapshot boundary; retry within the same
    // budget the mempool wait above already allowed.
    let fetch_deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let fetched = loop {
        let response = node.http_get(&format!("/api/tx/{txid}"))?;
        if response.status != 503 || std::time::Instant::now() >= fetch_deadline {
            break response;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    assert_eq!(fetched.status, 200, "tx fetch: {}", fetched.status);
    let body = fetched.json()?;
    assert_eq!(body["txid"], json!(txid));
    assert!(
        body["vin"][0]["prevout"].is_object(),
        "prevout projection missing: {body}"
    );
    assert_eq!(body["status"]["confirmed"], json!(false));

    let status = node.http_get(&format!("/api/tx/{txid}/status"))?;
    assert_eq!(status.json()?["confirmed"], json!(false));

    let hex = node.http_get(&format!("/api/tx/{txid}/hex"))?;
    assert_eq!(hex.status, 200);
    assert_eq!(hex.text()?, tx_hex(&spend));
    node.stop()
}

/// `getzmqnotifications` is only registered on zmq-feature builds;
/// without the feature the method is absent, not an erroring stub.
#[test]
fn zmq_notifications_feature_gated() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let reply = node.rpc_raw(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "getzmqnotifications", "params": []
    }))?;
    let code = reply["error"]["code"].as_i64();
    if code == Some(-32601) {
        // Feature not compiled in — the gated absence is correct.
        return node.stop();
    }
    let result = reply
        .get("result")
        .ok_or_else(|| Error::Assertion(format!("zmq reply: {reply}")))?;
    assert!(
        result.as_array().is_some(),
        "zmq notifications list: {result}"
    );
    node.stop()
}

/// `getcapabilities` reports the node's compiled service inventory.
#[test]
fn capabilities_reports_surface() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let caps = node.rpc("getcapabilities", &json!([]))?;
    assert!(
        caps.as_object().is_some_and(|o| !o.is_empty()),
        "capabilities must be a non-empty object: {caps}"
    );
    node.stop()
}
