//! Node lifecycle E2E: startup identity, readiness, graceful restart,
//! and config rejection.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::time::Duration;

use bitcoin_rs_e2e::helpers::{genesis_block, mine_bare_blocks, submit_genesis};
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, SpawnOptions, ValueExt};
use serde_json::json;

/// The node becomes ready on an empty datadir, reports the regtest
/// genesis as its tip, and answers the identity RPCs.
#[test]
fn startup_reports_regtest_identity() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;

    let info = node.rpc("getblockchaininfo", &json!([]))?;
    assert_eq!(info.str_field("chain")?, "regtest");
    let genesis = genesis_block().block_hash().to_string();
    assert_eq!(info.str_field("bestblockhash")?, genesis);
    assert_eq!(info.u64_field("blocks")?, 0);
    assert_eq!(info.u64_field("headers")?, 0);

    let count = node.rpc("getblockcount", &json!([]))?;
    assert_eq!(count, json!(0));
    let best = node.rpc("getbestblockhash", &json!([]))?;
    assert_eq!(best, json!(genesis));
    let at_zero = node.rpc("getblockhash", &json!([0]))?;
    assert_eq!(at_zero, best);

    node.stop()
}

/// A mined tip survives SIGTERM and is visible after a clean restart
/// over the same datadir.
#[test]
fn restart_preserves_chain_tip() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let hashes = mine_bare_blocks(&mut node, 5)?;
    let tip = hashes.last().unwrap().clone();
    assert_eq!(node.rpc("getblockcount", &json!([]))?, json!(5));
    assert_eq!(node.rpc("getbestblockhash", &json!([]))?, json!(tip));

    let datadir = node.take_datadir()?;
    node.stop()?;

    let mut restarted =
        ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &SpawnOptions::default(), datadir)?;
    assert_eq!(restarted.rpc("getblockcount", &json!([]))?, json!(5));
    assert_eq!(restarted.rpc("getbestblockhash", &json!([]))?, json!(tip));
    restarted.stop()
}

/// Broken startup configuration must exit the process instead of yielding a
/// half-configured node: unparseable config, an unknown `--network`, and an
/// RPC port already held by someone else.
#[test]
fn startup_rejects_broken_configuration() -> Result<()> {
    // The squatter holds the contested port for the whole table so the bind
    // case cannot accidentally succeed.
    let squatter = std::net::TcpListener::bind("127.0.0.1:0")?;
    let held = squatter.local_addr()?;
    let timeout = Some(Duration::from_secs(30));
    let cases = [
        (
            "malformed config file",
            SpawnOptions {
                toml_override: Some("this is [not = toml\n"),
                timeout,
                ..SpawnOptions::default()
            },
        ),
        (
            "unknown --network value",
            SpawnOptions {
                extra_args: &["--network", "no-such-net"],
                timeout,
                ..SpawnOptions::default()
            },
        ),
        (
            "rpc port already held",
            SpawnOptions {
                rpc_bind: Some(held),
                timeout,
                ..SpawnOptions::default()
            },
        ),
    ];
    for (label, options) in cases {
        let outcome = ProcessNode::spawn_with(Kind::BitcoinRs, &options);
        assert!(
            matches!(outcome, Err(Error::ChildExit { .. })),
            "{label} must not start a node: {outcome:?}"
        );
    }
    drop(squatter);
    Ok(())
}
