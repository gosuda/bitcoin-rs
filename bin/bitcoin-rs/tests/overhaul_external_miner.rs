//! External template consumer: spawn the public `bitcoin-rs` binary and
//! assemble a rendered GBT from real mempool content, then submit the solved
//! block over HTTP. T36 non-relay subset: no second P2P node, no relay faking.

use std::error::Error;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin_rs_e2e::helpers::{
    COINBASE_MATURITY, assemble_block_from_template, mature_funding, op_true_script, spend_anyone,
};
use bitcoin_rs_e2e::{Kind, ProcessNode, ValueExt};
use serde_json::{Value, json};

const FEE_SATS: u64 = 10_000;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
// CONTRACT: docs/contracts/external-api.md#API-14
// CONTRACT: docs/contracts/external-api.md#API-15
fn external_miner_assembles_template_and_submits_block() -> TestResult {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;

    // COINBASE_MATURITY+1 bare OP_TRUE blocks mature the height-1 coinbase;
    // the spend pays anyone-can-spend's P2WPKH sink minus the fee.
    let (outpoint, prevout) = mature_funding(&mut node)?;
    let spend = spend_anyone(outpoint, &prevout, FEE_SATS);
    let spend_hex = serialize_hex(&spend);
    let send = node.rpc("sendrawtransaction", &json!([spend_hex, 0]))?;
    assert!(
        send.as_str()
            .is_some_and(|s| s == spend.compute_txid().to_string()),
        "sendrawtransaction must return the spend txid: {send}"
    );

    let template = node.rpc("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    assert_eq!(
        template.u64_field("height")?,
        u64::from(COINBASE_MATURITY) + 2,
        "template must extend the current tip"
    );
    let template_txs = template
        .get("transactions")
        .and_then(Value::as_array)
        .ok_or("template must carry a transactions array")?;
    assert_eq!(
        template_txs.len(),
        1,
        "template must select the one admitted spend"
    );
    let entry = &template_txs[0];
    assert_eq!(
        entry.str_field("hash")?,
        spend.compute_wtxid().to_string(),
        "rendered hash must be the spend wtxid"
    );
    assert_eq!(
        entry.u64_field("fee")?,
        FEE_SATS,
        "rendered fee must match the spend fee"
    );
    assert!(
        entry.u64_field("weight")? > 0,
        "rendered weight must be positive"
    );
    let depends = entry
        .get("depends")
        .and_then(Value::as_array)
        .map_or(&[][..], |arr| arr.as_slice());
    assert!(depends.is_empty(), "single tx has no in-template depends");

    let block = assemble_block_from_template(&template, &op_true_script())?;
    let block_hex = serialize_hex(&block);
    let submit = node.rpc("submitblock", &json!([block_hex]))?;
    assert!(
        submit.is_null(),
        "submitblock must accept the external block: {submit}"
    );

    let info = node.rpc("getblockchaininfo", &json!([]))?;
    let tip_height = info.u64_field("blocks")?;
    assert_eq!(
        tip_height,
        u64::from(COINBASE_MATURITY) + 2,
        "tip must advance by one"
    );

    let mempool = node.rpc("getmempoolinfo", &json!([]))?;
    assert_eq!(
        mempool.u64_field("size")?,
        0,
        "mempool must be empty after block inclusion"
    );

    // `node` is dropped here, killing the child and cleaning up.
    let _ = node.stop();
    Ok(())
}
