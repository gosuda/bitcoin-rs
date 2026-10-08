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
        matches!(wrong_type["error"]["code"].as_i64(), Some(-32602 | -8 | -3)),
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
    assert_eq!(items[0]["id"], json!(1));
    assert_eq!(items[0]["result"], json!(0));
    assert_eq!(items[1]["id"], json!(2));
    assert_eq!(
        items[1]["result"],
        json!(genesis_block().block_hash().to_string())
    );

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
    assert_eq!(
        mempool.json()?,
        json!({"count": 0, "vsize": 0, "total_fee": 0, "fee_histogram": []}),
        "an untouched mempool must report zeroes, not just the fields"
    );

    let blocks = node.http_get("/api/blocks")?;
    assert_eq!(blocks.status, 200);
    assert_eq!(
        blocks.json()?[0]["id"],
        json!(hashes[3]),
        "recent blocks must lead with the tip"
    );

    let fees = node.http_get("/api/fee-estimates")?;
    assert_eq!(fees.status, 200);
    node.stop()
}

/// Esplora `POST /tx` broadcasts a raw transaction, and `GET /api/tx`
/// either projects it in full or reports the missing-index capability,
/// depending on whether `--txindex` is on.
#[test]
fn esplora_tx_broadcast_and_projection() -> Result<()> {
    for txindex in [false, true] {
        let extra_args: &[&str] = if txindex { &["--txindex=true"] } else { &[] };
        let mut node = ProcessNode::spawn_with(
            Kind::BitcoinRs,
            &SpawnOptions {
                extra_args,
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

        if !txindex {
            // Without txindex the full projection cannot resolve the spend's
            // confirmed prevout, so the capability contract answers 503
            // rather than an empty success.
            let fetched = node.http_get(&format!("/api/tx/{txid}"))?;
            assert_eq!(fetched.status, 503, "no txindex -> 503");
            node.stop()?;
            continue;
        }

        // With txindex, 503 also means "index changed during query; retry"
        // while the index crosses a snapshot boundary.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let fetched = loop {
            let response = node.http_get(&format!("/api/tx/{txid}"))?;
            if response.status != 503 || std::time::Instant::now() >= deadline {
                break response;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        assert_eq!(fetched.status, 200, "tx fetch: {}", fetched.status);
        let body = fetched.json()?;
        assert_eq!(body["txid"], json!(txid));
        assert_eq!(
            body["vin"][0]["prevout"]["value"],
            json!(prevout.value.to_sat()),
            "prevout projection must resolve the funded value: {body}"
        );
        assert_eq!(body["status"]["confirmed"], json!(false));

        let status = node.http_get(&format!("/api/tx/{txid}/status"))?;
        assert_eq!(status.json()?["confirmed"], json!(false));

        let hex = node.http_get(&format!("/api/tx/{txid}/hex"))?;
        assert_eq!(hex.status, 200);
        assert_eq!(hex.text()?, tx_hex(&spend));
        node.stop()?;
    }
    Ok(())
}
