//! P2P E2E against a pinned Bitcoin Core 31.1 peer: initial sync, peer
//! introspection, connection management, banning, and network toggles.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::time::Duration;

use bitcoin_rs_e2e::helpers::spawn_synced_pair;
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, ValueExt};
use serde_json::{Value, json};

/// Wait until `getconnectioncount` reports `want` peers.
fn wait_for_peers(node: &mut ProcessNode, label: &'static str, want: u64) -> Result<()> {
    node.wait_for(label, Duration::from_secs(20), |node| {
        let count = node
            .rpc("getconnectioncount", &json!([]))?
            .as_u64()
            .unwrap_or(u64::MAX);
        Ok((count == want || (want > 0 && count > want)).then_some(()))
    })
}

/// A fresh node answers its peerless surfaces with the empty/null values
/// Core uses, and the ban list round-trips.
#[test]
fn fresh_node_surfaces_and_ban_list() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;

    // `ping` answering null is a documented deviation from Core's scheduled
    // pong measurement; the rest are the empty address manager, peer table,
    // and added-node list of a node that has never connected.
    for (method, expected) in [
        ("ping", Value::Null),
        ("getnodeaddresses", json!([])),
        ("getpeerinfo", json!([])),
        ("getaddednodeinfo", json!([])),
        ("getconnectioncount", json!(0)),
        ("listbanned", json!([])),
    ] {
        assert_eq!(node.rpc(method, &json!([]))?, expected, "{method}");
    }

    assert_eq!(
        node.rpc("setban", &json!(["192.0.2.1", "add", 3600]))?,
        Value::Null
    );
    let banned = node.rpc("listbanned", &json!([]))?;
    let list = banned
        .as_array()
        .ok_or_else(|| Error::Assertion("listbanned not array".into()))?;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].str_field("address")?, "192.0.2.1/32");
    assert_eq!(list[0].u64_field("ban_duration")?, 3600);

    assert_eq!(node.rpc("clearbanned", &json!([]))?, Value::Null);
    assert_eq!(node.rpc("listbanned", &json!([]))?, json!([]));
    node.stop()
}

/// A fresh node syncs a Core-mined regtest chain to the same tip and keeps
/// following the peer past startup.
#[test]
fn node_syncs_and_follows_core_chain() -> Result<()> {
    let (mut core, mut node) = spawn_synced_pair(12)?;

    assert_eq!(node.rpc("getblockcount", &json!([]))?, json!(12));
    assert_eq!(
        node.rpc("getbestblockhash", &json!([]))?,
        core.rpc("getbestblockhash", &json!([]))?
    );
    // Hash-by-hash agreement over the synced range.
    for height in [1_u64, 6, 12] {
        assert_eq!(
            node.rpc("getblockhash", &json!([height]))?,
            core.rpc("getblockhash", &json!([height]))?,
            "height {height} diverged"
        );
    }

    // Blocks mined after the initial sync must still arrive.
    core.rpc(
        "generatetoaddress",
        &json!([6, bitcoin_rs_e2e::helpers::funding_address()?.to_string()]),
    )?;
    node.wait_block_count(18, Duration::from_secs(90))?;
    assert_eq!(
        node.rpc("getbestblockhash", &json!([]))?,
        core.rpc("getbestblockhash", &json!([]))?
    );
    node.stop()?;
    core.stop()
}

/// `getpeerinfo`/`getnetworkinfo`/`getnettotals` describe the live Core peer
/// and the transport it runs over.
#[test]
fn peer_and_network_introspection() -> Result<()> {
    let (core, mut node) = spawn_synced_pair(5)?;

    let peers = node.rpc("getpeerinfo", &json!([]))?;
    let peers = peers
        .as_array()
        .ok_or_else(|| Error::Assertion("getpeerinfo not array".into()))?;
    let peer = peers
        .first()
        .ok_or_else(|| Error::Assertion("no peer recorded".into()))?;
    assert_eq!(
        peer.str_field("addr")?,
        format!("127.0.0.1:{}", core.p2p_addr.port())
    );
    assert!(peer.u64_field("conntime")? > 0, "peer conntime: {peer}");
    assert!(
        peer.str_field("subver")?.starts_with("/Satoshi:"),
        "peer subver must echo the connected Core build: {peer}"
    );
    // `synced_blocks`/`synced_headers` are honest "not measured" (-1) in this
    // node rather than a guessed height.
    for field in ["synced_blocks", "synced_headers", "presynced_headers"] {
        assert_eq!(
            peer.field(field)?.as_i64(),
            Some(-1),
            "{field} must report unmeasured, not a guess: {peer}"
        );
    }

    let info = node.rpc("getnetworkinfo", &json!([]))?;
    assert!(info.u64_field("connections")? >= 1, "connections: {info}");
    assert_eq!(
        info.str_field("subversion")?,
        concat!("/bitcoin-rs:", env!("CARGO_PKG_VERSION"), "/")
    );
    assert_eq!(info.u64_field("protocolversion")?, 70016);
    let services = info["localservicesnames"]
        .as_array()
        .ok_or_else(|| Error::Assertion("localservicesnames".into()))?;
    for svc in ["NETWORK", "WITNESS"] {
        assert!(services.iter().any(|s| s == svc), "missing {svc}");
    }

    let totals = node.rpc("getnettotals", &json!([]))?;
    assert!(totals.u64_field("totalbytesrecv")? > 0);
    assert!(totals.u64_field("totalbytessent")? > 0);
    node.stop()?;
    core.stop()
}

/// Connectivity control: `disconnectnode` drops the live peer, `addnode`
/// restores it, and `setnetworkactive` gates the whole transport.
#[test]
fn connectivity_control_drops_and_restores_the_peer() -> Result<()> {
    let (core, mut node) = spawn_synced_pair(2)?;
    let core_addr = format!("127.0.0.1:{}", core.p2p_addr.port());

    assert_eq!(
        node.rpc("disconnectnode", &json!([core_addr]))?,
        Value::Null
    );
    wait_for_peers(&mut node, "peer disconnect", 0)?;
    assert_eq!(
        node.rpc("addnode", &json!([core_addr, "add"]))?,
        Value::Null
    );
    wait_for_peers(&mut node, "reconnect", 1)?;

    assert_eq!(node.rpc("setnetworkactive", &json!([false]))?, json!(false));
    wait_for_peers(&mut node, "network off", 0)?;
    assert_eq!(
        node.rpc("getnetworkinfo", &json!([]))?
            .get("networkactive")
            .and_then(Value::as_bool),
        Some(false)
    );

    assert_eq!(node.rpc("setnetworkactive", &json!([true]))?, json!(true));
    assert_eq!(
        node.rpc("addnode", &json!([core_addr, "add"]))?,
        Value::Null
    );
    wait_for_peers(&mut node, "network on", 1)?;
    node.stop()?;
    core.stop()
}
