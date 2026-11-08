use bitcoin::Block;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin_rs_e2e::helpers::{
    build_chain, coinbase_at, mature_funding, mine_bare_blocks, p2sh_true_script, spend_anyone,
    submit_genesis, tx_hex,
};
use bitcoin_rs_e2e::node::workspace;
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, SpawnOptions, ValueExt};
use sonic_rs::{JsonValueTrait as _, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const EPOCH3_FIXTURE_BLOCKS: u32 = 30;
const EPOCH3_SUFFIX_FEE_SATS: u64 = 1_000;
const EPOCH3_SUFFIX_CANONICAL_TIP: u64 = 104;

pub(crate) fn epoch3_fixture_dir() -> PathBuf {
    workspace().join("tools/storage-convert/tests/fixtures/epoch3-regtest")
}

pub(crate) fn epoch3_expected_path() -> PathBuf {
    workspace().join("tools/storage-convert/tests/fixtures/epoch3-regtest.expected.json")
}

pub(crate) fn epoch3_suffix_fixture_dir() -> PathBuf {
    workspace().join("tools/storage-convert/tests/fixtures/epoch3-regtest-suffix")
}

pub(crate) fn epoch3_suffix_expected_path() -> PathBuf {
    workspace().join("tools/storage-convert/tests/fixtures/epoch3-regtest-suffix.expected.json")
}

fn copy_datadir(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_text = name.to_string_lossy();
        if name_text == "LOCK"
            || name_text.starts_with("LOG")
            || name_text.ends_with(".lock")
            || name_text == "node.toml"
        {
            continue;
        }
        let source = entry.path();
        let destination = to.join(&name);
        if entry.file_type()?.is_dir() {
            copy_datadir(&source, &destination)?;
        } else {
            fs::copy(&source, &destination)?;
        }
    }
    Ok(())
}

#[test]
#[ignore = "regenerates the epoch-3 converter fixture; set BITCOIN_RS_NODE to a pre-Phase-3 bitcoin-rs"]
fn regenerate_epoch3_converter_fixture() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    mine_bare_blocks(&mut node, EPOCH3_FIXTURE_BLOCKS)?;
    let info = node.rpc("getblockchaininfo", &json!([]))?;
    let txout = node.rpc("gettxoutsetinfo", &json!([]))?;
    let datadir = node.stop_keep_datadir()?;

    let target = epoch3_fixture_dir();
    if target.exists() {
        fs::remove_dir_all(&target)?;
    }
    copy_datadir(&datadir.path().join("node"), &target)?;

    let expected = json!({
        "height": info.u64_field("blocks")?,
        "tip_hash": info.str_field("bestblockhash")?,
        "txouts": txout.u64_field("txouts")?,
        "total_amount": txout.field("total_amount")?.clone(),
        "hash_serialized_3": txout.str_field("hash_serialized_3")?,
    });
    fs::write(
        epoch3_expected_path(),
        sonic_rs::to_string_pretty(&expected)
            .map_err(|error| Error::Assertion(error.to_string()))?,
    )?;
    Ok(())
}

#[test]
#[ignore = "regenerates the epoch-3 suffix fixture; set BITCOIN_RS_NODE to a pre-Phase-3 bitcoin-rs"]
fn regenerate_epoch3_suffix_fixture() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let (funding_outpoint, funding_prevout) = mature_funding(&mut node)?;
    let funding = coinbase_at(&mut node, 1)?;
    let untouched = coinbase_at(&mut node, 2)?;
    let datadir = node.stop_keep_datadir()?;

    let mut node =
        ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &SpawnOptions::default(), datadir)?;
    let spend = spend_anyone(funding_outpoint, &funding_prevout, EPOCH3_SUFFIX_FEE_SATS);
    let descriptor = format!("raw({:x})", p2sh_true_script());
    node.rpc("generateblock", &json!([descriptor, [tx_hex(&spend)]]))?;
    mine_bare_blocks(&mut node, 2)?;
    let canonical = coinbase_at(&mut node, EPOCH3_SUFFIX_CANONICAL_TIP)?;
    let canonical_hash = node
        .rpc("getblockhash", &json!([EPOCH3_SUFFIX_CANONICAL_TIP]))?
        .as_str()
        .ok_or_else(|| Error::Assertion("canonical tip hash".into()))?
        .to_owned();

    let parent_hash = node
        .rpc("getblockhash", &json!([EPOCH3_SUFFIX_CANONICAL_TIP - 1]))?
        .as_str()
        .ok_or_else(|| Error::Assertion("parent hash".into()))?
        .to_owned();
    let parent_hex = node
        .rpc("getblock", &json!([parent_hash, 0]))?
        .as_str()
        .ok_or_else(|| Error::Assertion("parent block hex".into()))?
        .to_owned();
    let parent: Block =
        deserialize_hex(&parent_hex).map_err(|error| Error::Assertion(error.to_string()))?;
    let fork = build_chain(&parent, 1, 0x77, 104).remove(0);
    node.rpc("submitblock", &json!([serialize_hex(&fork)]))?;

    let info = node.rpc("getblockchaininfo", &json!([]))?;
    let txout = node.rpc("gettxoutsetinfo", &json!([]))?;
    if info.str_field("bestblockhash")? != canonical_hash {
        return Err(Error::Assertion(
            "the stale fork must not displace the canonical tip".into(),
        ));
    }
    node.send_sigkill();
    let _ = node.wait_exit_code(Duration::from_secs(30));
    let datadir = node.take_datadir()?;

    let target = epoch3_suffix_fixture_dir();
    if target.exists() {
        fs::remove_dir_all(&target)?;
    }
    copy_datadir(&datadir.path().join("node"), &target)?;

    let expected = json!({
        "height": info.u64_field("blocks")?,
        "tip_hash": info.str_field("bestblockhash")?,
        "txouts": txout.u64_field("txouts")?,
        "total_amount": txout.field("total_amount")?.clone(),
        "hash_serialized_3": txout.str_field("hash_serialized_3")?,
        "checkpoint_height": 101,
        "funding_txid": funding.compute_txid().to_string(),
        "funding_vout": funding_outpoint.vout,
        "spend_txid": spend.compute_txid().to_string(),
        "untouched_txid": untouched.compute_txid().to_string(),
        "canonical_coinbase_txid": canonical.compute_txid().to_string(),
        "stale_coinbase_txid": fork.txdata[0].compute_txid().to_string(),
    });
    fs::write(
        epoch3_suffix_expected_path(),
        sonic_rs::to_string_pretty(&expected)
            .map_err(|error| Error::Assertion(error.to_string()))?,
    )?;
    Ok(())
}
