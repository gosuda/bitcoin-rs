//! Mining-surface E2E: block templates, `submitblock`/`submitheader`,
//! `generateblock`/`generatetoaddress`, and mining introspection.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin_rs_e2e::helpers::{
    COINBASE_MATURITY, assemble_block_from_template, coinbase_at, funding_address, funding_output,
    genesis_block, mine_bare_blocks, op_true_script, spend_anyone, submit_genesis, tx_hex,
};
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, ValueExt};
use serde_json::{Value, json};

/// `getblocktemplate` exposes the BIP22 fields a miner needs.
#[test]
fn block_template_shape() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let hashes = mine_bare_blocks(&mut node, 3)?;

    let template = node.rpc("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    assert_eq!(template.str_field("previousblockhash")?, hashes[2]);
    assert_eq!(template.u64_field("height")?, 4);
    assert_eq!(template.u64_field("coinbasevalue")?, 50_u64 * 100_000_000);
    assert_eq!(template.str_field("bits")?, "207fffff");
    assert_eq!(
        template.str_field("target")?,
        "7fffff0000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(template.str_field("noncerange")?, "00000000ffffffff");
    assert_eq!(template.u64_field("sigoplimit")?, 80_000);
    assert_eq!(template.u64_field("sizelimit")?, 4_000_000);
    assert_eq!(template.u64_field("weightlimit")?, 4_000_000);
    assert!(
        template.u64_field("mintime")? <= template.u64_field("curtime")?,
        "mintime must not exceed curtime: {template}"
    );
    let capabilities = template
        .get("capabilities")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Assertion("capabilities missing".into()))?;
    assert!(capabilities.iter().any(|c| c == "longpoll"));
    let mutable = template
        .get("mutable")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Assertion("mutable missing".into()))?;
    assert!(mutable.iter().any(|m| m == "prevblock"));
    node.stop()
}

/// A template assembled offline grinds to valid proof-of-work: its header is
/// admitted by `submitheader`, the matching body then connects via
/// `submitblock`, and the applied tip advances to it.
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

    // Re-submitting an applied block is a duplicate, not an error, and
    // genesis is always already known.
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

/// Malformed block/header hex and unmineable `generateblock` requests each
/// carry Core's distinct error code.
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

/// `generatetoaddress` pays the requested script in the coinbase.
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

/// Mining introspection reports tip height, difficulty, and a non-negative
/// network hashrate estimate.
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

    // The two mining surfaces must report one estimate, not two.
    assert_eq!(
        info.field("networkhashps")?,
        &node.rpc("getnetworkhashps", &json!([]))?,
        "getmininginfo and getnetworkhashps disagree"
    );
    node.stop()
}

/// A transaction that pays full fee rate is included when named in
/// `generateblock`'s tx list, and the block's tx root verifies.
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
