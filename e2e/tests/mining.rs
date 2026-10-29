//! Mining-surface E2E: block templates, `submitblock`/`submitheader`,

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin_rs_e2e::helpers::{
    COINBASE_MATURITY, assemble_block_from_template, coinbase_at, funding_address, funding_output,
    genesis_block, mine_bare_blocks, op_true_script, spend_anyone, submit_genesis, tx_hex,
};
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, ValueExt};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

#[test]
fn template_assembly_header_then_block() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let _ = mine_bare_blocks(&mut node, 2)?;

    let template = node.rpc("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    let block = assemble_block_from_template(&template, &op_true_script())?;

    let header = node.rpc("submitheader", &json!([serialize_hex(&block.header)]))?;
    assert!(header.is_null(), "submitheader: {header}");
    let body = node.rpc("submitblock", &json!([serialize_hex(&block)]))?;
    assert!(body.is_null(), "body connects after header: {body}");

    assert_eq!(node.rpc("getblockcount", &json!([]))?, json!(3));
    assert_eq!(
        node.rpc("getbestblockhash", &json!([]))?,
        json!(block.block_hash().to_string())
    );

    let tip_hex = node.rpc("getblock", &json!([block.block_hash().to_string(), 0]))?;
    assert_eq!(
        node.rpc("submitblock", &json!([tip_hex]))?,
        json!("duplicate")
    );
    assert_eq!(
        node.rpc("submitblock", &json!([serialize_hex(&genesis_block())]))?,
        json!("duplicate")
    );
    node.stop()
}

#[test]
fn mining_rejections_carry_core_error_codes() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;

    let cases = [
        ("submitblock", json!(["deadbeef"]), -22),
        ("submitheader", json!(["00ff00"]), -22),
        ("generateblock", json!(["not-a-descriptor", []]), -5),
        (
            "generateblock",
            json!(["raw(51)", [format!("{:064x}", 0)]]),
            -5,
        ),
    ];
    for (method, params, code) in cases {
        let reply = node.rpc_raw(&json!({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params
        }))?;
        assert_eq!(reply["error"]["code"], json!(code), "{method}: {reply}");
    }
    node.stop()
}

#[test]
fn generatetoaddress_pays_address() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let address = funding_address()?;

    let result = node.rpc("generatetoaddress", &json!([3, address.to_string()]))?;
    let hashes = result
        .as_array()
        .ok_or_else(|| Error::Assertion("generatetoaddress not array".into()))?;
    assert_eq!(hashes.len(), 3);
    assert_eq!(node.rpc("getblockcount", &json!([]))?, json!(3));

    let coinbase = coinbase_at(&mut node, 1)?;
    assert_eq!(
        coinbase.output[0].script_pubkey,
        address.script_pubkey(),
        "coinbase output 0 must pay the requested address"
    );
    node.stop()
}

#[test]
fn mining_info_and_hashps() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let _ = mine_bare_blocks(&mut node, 5)?;

    let info = node.rpc("getmininginfo", &json!([]))?;
    assert_eq!(info.u64_field("blocks")?, 5);
    assert_eq!(info.str_field("chain")?, "regtest");
    assert_eq!(info.str_field("bits")?, "207fffff");
    assert_eq!(info["next"]["height"], json!(6));

    let hashps = node.rpc("getnetworkhashps", &json!([]))?;
    let value = hashps
        .as_f64()
        .ok_or_else(|| Error::Assertion("getnetworkhashps not numeric".into()))?;
    assert!(value >= 0.0, "negative network hashrate: {value}");
    assert_eq!(
        info.field("networkhashps")?,
        &hashps,
        "getmininginfo and getnetworkhashps disagree"
    );
    assert!(info.field("difficulty")?.as_f64().is_some());
    node.stop()
}

#[test]
fn generateblock_with_listed_tx_verifies() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let _ = mine_bare_blocks(&mut node, COINBASE_MATURITY + 1)?;
    let coinbase = coinbase_at(&mut node, 1)?;
    let (outpoint, prevout) = funding_output(&coinbase)?;

    let spend = spend_anyone(outpoint, &prevout, 1_000);
    let txid = spend.compute_txid().to_string();
    node.rpc("sendrawtransaction", &json!([tx_hex(&spend)]))?;

    let mined = node.rpc("generateblock", &json!(["raw(51)", [txid]]))?;
    let hash = mined.str_field("hash")?;
    let block_hex = node.rpc("getblock", &json!([hash, 0]))?;
    let block: bitcoin::Block = deserialize_hex(
        block_hex
            .as_str()
            .ok_or_else(|| Error::Assertion("hex".into()))?,
    )
    .map_err(|e| Error::Assertion(format!("decode: {e}")))?;
    assert_eq!(block.txdata.len(), 2);
    assert_eq!(block.txdata[1].compute_txid().to_string(), txid);
    assert!(block.check_merkle_root());
    node.stop()
}
