//! Active-tip waits against an unmodified pinned Core process.

#![expect(clippy::expect_used)]

use bitcoin_rs_e2e::helpers::{mine_bare_blocks, submit_genesis};
use bitcoin_rs_e2e::rpc::Connection;
use bitcoin_rs_e2e::{Kind, ProcessNode, Result, SpawnOptions};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

fn envelope(method: &str, params: Value) -> Value {
    let mut request = json!({"jsonrpc":"2.0","id":1,"method":method});
    request["params"] = params;
    request
}

fn waiting(address: SocketAddr, method: &str, params: Value) -> JoinHandle<Result<Value>> {
    let request = envelope(method, params);
    std::thread::spawn(move || {
        Connection::new(address).rpc(
            &request,
            ("parity", "parity"),
            Instant::now() + Duration::from_secs(8),
        )
    })
}

fn current(node: &mut ProcessNode) -> Result<Value> {
    Ok(
        json!({"hash":node.rpc("getbestblockhash", &json!([]))?,"height":node.rpc("getblockcount", &json!([]))?}),
    )
}

fn deliver(core: &mut ProcessNode, candidate: &mut ProcessNode, hash: &str) -> Result<()> {
    let raw = core.rpc("getblock", &json!([hash, 0]))?;
    assert!(candidate.rpc("submitblock", &json!([raw]))?.is_null());
    Ok(())
}

#[test]
fn wait_parameters_and_timeouts_match_core_with_declared_short_help() -> Result<()> {
    let mut core = ProcessNode::spawn(Kind::Core)?;
    let mut candidate = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut candidate)?;
    let block = mine_bare_blocks(&mut core, 1)?;
    deliver(&mut core, &mut candidate, &block[0])?;
    let tip = current(&mut core)?;
    let hash = tip["hash"].as_str().expect("tip hash");
    let unknown = "00".repeat(32);
    let genesis = core.rpc("getblockhash", &json!([0]))?;
    let cases = vec![
        ("waitfornewblock", json!([1])),
        ("waitfornewblock", json!([1, null])),
        ("waitfornewblock", json!([1, hash])),
        ("waitfornewblock", json!([0, unknown])),
        (
            "waitfornewblock",
            json!({"timeout":null,"current_tip":unknown}),
        ),
        ("waitfornewblock", json!({"args":[1],"current_tip":hash})),
        ("waitforblock", json!([hash])),
        ("waitforblock", json!([hash, null])),
        ("waitforblock", json!([genesis, 1])),
        ("waitforblock", json!([unknown, 1])),
        ("waitforblock", json!({"blockhash":hash,"timeout":1})),
        ("waitforblockheight", json!([-1])),
        ("waitforblockheight", json!([-2_147_483_648_i64, null])),
        ("waitforblockheight", json!([2, 1])),
        ("waitforblockheight", json!([2_147_483_647_i64, 1])),
        ("waitforblockheight", json!({"args":[1],"timeout":null})),
        ("waitfornewblock", json!([-1])),
        ("waitfornewblock", json!([1.0])),
        ("waitfornewblock", json!([1.5])),
        ("waitfornewblock", json!([2_147_483_648_i64])),
        ("waitfornewblock", json!(["x"])),
        ("waitfornewblock", json!([true])),
        ("waitfornewblock", json!([1, 0])),
        ("waitfornewblock", json!([1, "abc"])),
        ("waitfornewblock", json!(["x", 0])),
        ("waitfornewblock", json!({"args":[null],"timeout":null})),
        ("waitforblockheight", json!([null])),
        ("waitforblockheight", json!([1.0, 1])),
        ("waitforblockheight", json!(["a", 1])),
        ("waitforblockheight", json!([2_147_483_648_i64, 1])),
        ("waitforblockheight", json!({"timeout":1})),
        ("waitforblock", json!([null])),
        ("waitforblock", json!(["abc", 1])),
        ("waitforblock", json!([0, 1])),
    ];
    let mut evidence = Vec::new();
    for (method, params) in cases {
        let request = envelope(method, params);
        let expected = core.rpc_raw(&request)?;
        let actual = candidate.rpc_raw(&request)?;
        evidence.push(json!({"request":request,"core":expected,"candidate":actual}));
        assert_eq!(actual, expected, "{request}");
    }
    for (method, params) in [
        ("waitfornewblock", json!([1, null, 3])),
        ("waitforblockheight", json!([])),
        ("waitforblock", json!([])),
    ] {
        let request = envelope(method, params);
        let expected = core.rpc_raw(&request)?;
        let actual = candidate.rpc_raw(&request)?;
        assert_eq!(actual["error"]["code"], expected["error"]["code"]);
        assert!(
            expected["error"]["message"]
                .as_str()
                .expect("Core help")
                .starts_with(actual["error"]["message"].as_str().expect("concise usage"))
        );
        evidence.push(json!({"request":request,"core":expected,"candidate":actual,"deviation":"concise arity usage omits generated help"}));
    }
    std::fs::write(
        candidate.evidence.join("wait-parameter-comparisons.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    candidate.stop()?;
    core.stop()
}

fn check_header_only_waits(
    node: &mut ProcessNode,
    raw: &str,
    hash: &str,
    applied: &Value,
) -> Result<()> {
    assert!(node.rpc("submitheader", &json!([&raw[..160]]))?.is_null());
    // Each finite request completes after header admission. Its answer proves
    // the header-only state still exposes the old applied tip, regardless of
    // scheduling. The owner's private notification gate proves parked races.
    for (method, params) in [
        ("waitfornewblock", json!([1, applied["hash"]])),
        ("waitforblock", json!([hash, 1])),
        ("waitforblockheight", json!([2, 1])),
    ] {
        assert_eq!(
            node.rpc(method, &params)?,
            *applied,
            "{method} after header"
        );
    }
    Ok(())
}

#[test]
fn waits_follow_applied_blocks_reorgs_restart_and_shutdown_like_core() -> Result<()> {
    let mut core = ProcessNode::spawn(Kind::Core)?;
    let mut candidate = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut candidate)?;
    let first = mine_bare_blocks(&mut core, 1)?;
    deliver(&mut core, &mut candidate, &first[0])?;
    let before = current(&mut core)?;
    let next = core.rpc("generateblock", &json!(["raw(51)", [], false]))?;
    let next_hash = next["hash"].as_str().expect("new hash");
    let next_raw = next["hex"].as_str().expect("new block");
    for node in [&mut core, &mut candidate] {
        check_header_only_waits(node, next_raw, next_hash, &before)?;
    }
    let mut tasks = Vec::new();
    for address in [core.rpc_addr, candidate.rpc_addr] {
        for (method, params) in [
            ("waitfornewblock", json!([0, before["hash"]])),
            ("waitforblock", json!([next_hash])),
            ("waitforblockheight", json!([2])),
        ] {
            tasks.push(waiting(address, method, params));
        }
    }
    for node in [&mut core, &mut candidate] {
        assert!(node.rpc("submitblock", &json!([next_raw]))?.is_null());
    }
    let expected = json!({"jsonrpc":"2.0","id":1,"result":{"hash":next_hash,"height":2}});
    for task in tasks {
        assert_eq!(task.join().expect("waiter")?, expected);
    }

    // A committed rollback wakes hash-change observers at the lower height.
    let mut tasks = Vec::new();
    for node in [&mut core, &mut candidate] {
        tasks.push(waiting(
            node.rpc_addr,
            "waitfornewblock",
            json!([0, next_hash]),
        ));
        assert!(node.rpc("invalidateblock", &json!([next_hash]))?.is_null());
    }
    for task in tasks {
        assert_eq!(task.join().expect("rollback waiter")?["result"], before);
    }
    // A same-height replacement is a different hash, and the old tip/ancestor
    // does not satisfy waitforblock merely because its body is still known.
    let replacement = core.rpc("generateblock", &json!(["raw(52)", []]))?;
    let replacement_hash = replacement["hash"].as_str().expect("replacement");
    assert_ne!(replacement_hash, next_hash);
    deliver(&mut core, &mut candidate, replacement_hash)?;
    for (method, params) in [
        ("waitfornewblock", json!([0, next_hash])),
        ("waitforblock", json!([next_hash, 1])),
        ("waitforblockheight", json!([2])),
    ] {
        assert_eq!(candidate.rpc(method, &params)?, core.rpc(method, &params)?);
    }
    let restored_tip = current(&mut candidate)?;
    let datadir = candidate.stop_keep_datadir()?;
    let mut candidate =
        ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &SpawnOptions::default(), datadir)?;
    assert_eq!(
        candidate.rpc("waitforblockheight", &json!([2]))?,
        restored_tip,
        "restart must use restored applied publication"
    );
    let mut tasks = Vec::new();
    for node in [core, candidate] {
        let expected = restored_tip.clone();
        let address = node.rpc_addr;
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let task = std::thread::spawn(move || {
            // Reuse an established HTTP connection to avoid racing TCP accept.
            // This black-box scenario observes a shutdown response; it does
            // not expose the point where the wait predicate parks. Deterministic
            // admitted cancellation is proved by the owner/real-server tests.
            let mut connection = Connection::new(address);
            connection.rpc(
                &envelope("getblockcount", json!([])),
                ("parity", "parity"),
                Instant::now() + Duration::from_secs(2),
            )?;
            ready_tx.send(()).expect("shutdown test receiver");
            connection.rpc(
                &envelope("waitforblockheight", json!([100_000])),
                ("parity", "parity"),
                Instant::now() + Duration::from_secs(8),
            )
        });
        ready_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("prewarmed RPC worker");
        std::thread::sleep(Duration::from_millis(100));
        assert!(!task.is_finished());
        node.stop()?;
        tasks.push((task, expected));
    }
    for (task, expected) in tasks {
        assert_eq!(task.join().expect("shutdown waiter")?["result"], expected);
    }
    Ok(())
}
