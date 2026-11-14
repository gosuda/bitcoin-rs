use std::fs;
use std::path::Path;
use std::process::Command;

use bitcoin_rs_e2e::helpers::node_stderr;
use bitcoin_rs_e2e::node::bitcoin_rs_storage_convert_binary;
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, SpawnOptions, ValueExt};
use sonic_rs::{Value, json};
use tempfile::TempDir;

use crate::converter_fixture::{
    epoch3_expected_path, epoch3_fixture_dir, epoch3_suffix_expected_path,
    epoch3_suffix_fixture_dir,
};

fn convert_epoch3_into(from: &Path, to: &Path) -> Result<()> {
    let output = Command::new(bitcoin_rs_storage_convert_binary()?)
        .arg("--from")
        .arg(from)
        .arg("--to")
        .arg(to)
        .output()?;
    if !output.status.success() {
        return Err(Error::Assertion(format!(
            "storage-convert 3 -> 4 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

fn read_expected() -> Result<Value> {
    let text = fs::read_to_string(epoch3_expected_path())?;
    sonic_rs::from_str(&text).map_err(|error| Error::Assertion(error.to_string()))
}

#[test]
fn converted_epoch3_datadir_serves_source_tip_and_coin_set() -> Result<()> {
    let expected = read_expected()?;
    let datadir = TempDir::new()?;
    let node_dir = datadir.path().join("node");
    fs::create_dir_all(&node_dir)?;
    convert_epoch3_into(&epoch3_fixture_dir(), &node_dir)?;

    let mut node =
        ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &SpawnOptions::default(), datadir)?;
    let info = node.rpc("getblockchaininfo", &json!([]))?;
    assert_eq!(info.u64_field("blocks")?, expected.u64_field("height")?);
    assert_eq!(
        info.str_field("bestblockhash")?,
        expected.str_field("tip_hash")?
    );

    let txout = node.rpc("gettxoutsetinfo", &json!([]))?;
    assert_eq!(txout.u64_field("txouts")?, expected.u64_field("txouts")?);
    assert_eq!(
        txout.str_field("hash_serialized_3")?,
        expected.str_field("hash_serialized_3")?
    );
    assert_eq!(
        txout.field("total_amount")?,
        expected.field("total_amount")?
    );
    node.stop()
}

fn read_suffix_expected() -> Result<Value> {
    let text = fs::read_to_string(epoch3_suffix_expected_path())?;
    sonic_rs::from_str(&text).map_err(|error| Error::Assertion(error.to_string()))
}

#[test]
fn converted_epoch3_suffix_datadir_resumes_at_durable_head() -> Result<()> {
    let expected = read_suffix_expected()?;
    let datadir = TempDir::new()?;
    let node_dir = datadir.path().join("node");
    fs::create_dir_all(&node_dir)?;
    convert_epoch3_into(&epoch3_suffix_fixture_dir(), &node_dir)?;

    let mut node =
        ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &SpawnOptions::default(), datadir)?;
    let info = node.rpc("getblockchaininfo", &json!([]))?;
    assert_eq!(info.u64_field("blocks")?, expected.u64_field("height")?);
    assert_eq!(
        info.str_field("bestblockhash")?,
        expected.str_field("tip_hash")?
    );
    let txout = node.rpc("gettxoutsetinfo", &json!([]))?;
    assert_eq!(txout.u64_field("txouts")?, expected.u64_field("txouts")?);
    assert_eq!(
        txout.str_field("hash_serialized_3")?,
        expected.str_field("hash_serialized_3")?
    );
    if !node_stderr(&node).contains("restored chainstate checkpoint") {
        return Err(Error::Assertion(
            "the node must resume from the published checkpoint, not replay from genesis".into(),
        ));
    }
    node.stop()
}
