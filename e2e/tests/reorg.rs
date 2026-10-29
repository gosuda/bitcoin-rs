//! Reorg E2E: `invalidateblock` rewinds, a heavier competing Core chain

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::time::Duration;

use bitcoin_rs_e2e::helpers::{
    mine_bare_blocks, mine_blocks_to, spawn_synced_pair, submit_genesis,
};
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, SpawnOptions, ValueExt, mock_time};
use sonic_rs::{JsonContainerTrait as _, Value, json};

#[test]
fn invalidateblock_rewinds_tip() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let hashes = mine_bare_blocks(&mut node, 5)?;

    assert_eq!(
        node.rpc("invalidateblock", &json!([hashes[2]]))?,
        Value::new()
    );
    assert_eq!(node.rpc("getblockcount", &json!([]))?, json!(2));
    assert_eq!(node.rpc("getbestblockhash", &json!([]))?, json!(hashes[1]));

    let tips = node.rpc("getchaintips", &json!([]))?;
    let tips = tips
        .as_array()
        .ok_or_else(|| Error::Assertion("getchaintips not array".into()))?;
    assert!(tips.len() >= 2, "invalidated branch must remain visible");
    let dead = tips
        .iter()
        .find(|t| t.str_field("hash").ok() == Some(hashes[4].as_str()))
        .ok_or_else(|| Error::Assertion("invalidated tip missing".into()))?;
    assert!(
        matches!(
            dead.str_field("status")?,
            "invalid" | "headers-only" | "valid-headers" | "valid-fork"
        ),
        "dead branch status: {dead}"
    );

    let fork = mine_blocks_to(&mut node, 4, "raw(52)")?;
    assert_ne!(fork[0], hashes[2]);
    assert_eq!(node.rpc("getblockcount", &json!([]))?, json!(6));
    node.stop()
}

#[test]
fn core_reorg_repoints_node_tip() -> Result<()> {
    let (mut core, mut node) = spawn_synced_pair(6)?;

    let hash_at_3 = core.rpc("getblockhash", &json!([3]))?;
    assert_eq!(
        core.rpc("invalidateblock", &json!([hash_at_3]))?,
        Value::new()
    );
    assert_eq!(core.rpc("getblockcount", &json!([]))?, json!(2));

    core.rpc("setmocktime", &json!([mock_time() + 3_600]))?;

    core.rpc(
        "generatetoaddress",
        &json!([8, bitcoin_rs_e2e::helpers::funding_address()?.to_string()]),
    )?;

    node.wait_block_count(10, Duration::from_mins(2))?;
    let node_tip = node.rpc("getbestblockhash", &json!([]))?;
    let core_tip = core.rpc("getbestblockhash", &json!([]))?;
    assert_eq!(node_tip, core_tip, "node must re-org to the heavier chain");

    let at_6 = node.rpc("getblockhash", &json!([6]))?;
    assert_eq!(
        at_6,
        core.rpc("getblockhash", &json!([6]))?,
        "re-orged height must serve the new branch"
    );
    node.stop()?;
    core.stop()
}

#[test]
fn restart_mid_chain_resumes_sync() -> Result<()> {
    let (mut core, node) = spawn_synced_pair(5)?;

    let datadir = node.stop_keep_datadir()?;
    let connect = format!("--connect=127.0.0.1:{}", core.p2p_addr.port());
    let mut node = ProcessNode::spawn_in_datadir(
        Kind::BitcoinRs,
        &SpawnOptions {
            extra_args: &[connect.as_str()],
            ..SpawnOptions::default()
        },
        datadir,
    )?;
    core.rpc(
        "generatetoaddress",
        &json!([3, bitcoin_rs_e2e::helpers::funding_address()?.to_string()]),
    )?;
    node.wait_block_count(8, Duration::from_secs(90))?;
    assert_eq!(
        node.rpc("getbestblockhash", &json!([]))?,
        core.rpc("getbestblockhash", &json!([]))?
    );
    node.stop()?;
    core.stop()
}
