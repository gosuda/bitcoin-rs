//! Chain-state query E2E: block/height lookups, chain tips, UTXO set
//! statistics, proofs, and index/introspection surfaces.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin_rs_e2e::helpers::{
    coinbase_at, funding_address, funding_output, genesis_block, mine_bare_blocks, submit_genesis,
};
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, ValueExt};
use serde_json::{Value, json};

/// Height/hash lookups agree with each other once blocks exist.
#[test]
fn height_and_hash_queries() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let hashes = mine_bare_blocks(&mut node, 5)?;

    assert_eq!(node.rpc("getblockcount", &json!([]))?, json!(5));
    let tip = node.rpc("getbestblockhash", &json!([]))?;
    assert_eq!(tip, json!(hashes[4]));

    let genesis = genesis_block().block_hash().to_string();
    for (height, expected) in hashes.iter().enumerate() {
        let at = node.rpc("getblockhash", &json!([height + 1]))?;
        assert_eq!(&at, &json!(expected));
    }
    assert_eq!(
        node.rpc("getblockhash", &json!([0]))?,
        json!(genesis),
        "height 0 is genesis"
    );

    // Core answers out-of-range heights with -8 RPC_INVALID_PARAMETER.
    for height in [99_i64, -1] {
        let beyond = node.rpc_raw(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "getblockhash", "params": [height]
        }))?;
        assert_eq!(beyond["error"]["code"], json!(-8), "height {height}");
    }
    node.stop()
}

/// `getblock` verbosities 0/1/2, `getblockheader`, and `getblockstats`
/// report one consistent view of a block.
#[test]
fn block_views_agree() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let hashes = mine_bare_blocks(&mut node, 3)?;
    let hash = &hashes[2];

    let raw = node.rpc("getblock", &json!([hash, 0]))?;
    let raw_hex = raw
        .as_str()
        .ok_or_else(|| Error::Assertion("getblock(0) not a string".into()))?;
    let parsed: bitcoin::Block =
        deserialize_hex(raw_hex).map_err(|e| Error::Assertion(format!("block decode: {e}")))?;
    assert_eq!(parsed.block_hash().to_string(), *hash);

    let verbose = node.rpc("getblock", &json!([hash, 1]))?;
    assert_eq!(verbose.str_field("hash")?, *hash);
    assert_eq!(verbose.u64_field("height")?, 3);
    assert_eq!(verbose.u64_field("confirmations")?, 1);
    assert_eq!(verbose.u64_field("nTx")?, 1);
    assert_eq!(verbose.str_field("previousblockhash")?, hashes[1]);
    assert!(verbose.get("nextblockhash").is_none_or(Value::is_null));

    let with_tx = node.rpc("getblock", &json!([hash, 2]))?;
    let txs = with_tx
        .get("tx")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Assertion("getblock(2) lacks tx".into()))?;
    assert_eq!(txs.len(), 1);
    assert_eq!(
        txs[0].str_field("txid")?,
        parsed.txdata[0].compute_txid().to_string(),
        "verbose tx must be the block's coinbase"
    );

    let header = node.rpc("getblockheader", &json!([hash]))?;
    // The header view must agree field-for-field with the verbose block.
    for field in ["hash", "height", "time", "mediantime", "bits", "nonce"] {
        assert_eq!(
            header.field(field)?,
            verbose.field(field)?,
            "getblockheader disagrees on {field}"
        );
    }

    let stats = node.rpc("getblockstats", &json!([hash]))?;
    assert_eq!(stats.u64_field("height")?, 3);
    assert_eq!(stats.str_field("blockhash")?, *hash);
    assert_eq!(stats.u64_field("subsidy")?, 5_000_000_000);
    assert_eq!(stats.u64_field("txs")?, 1);
    node.stop()
}

/// `getchaintips` reports the single active tip and `getchaintxstats` the
/// cumulative transaction count.
#[test]
fn chain_tips_and_tx_stats() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let hashes = mine_bare_blocks(&mut node, 4)?;

    let tips = node.rpc("getchaintips", &json!([]))?;
    let tips = tips
        .as_array()
        .ok_or_else(|| Error::Assertion("getchaintips not an array".into()))?;
    assert_eq!(tips.len(), 1);
    assert_eq!(tips[0].str_field("status")?, "active");
    assert_eq!(tips[0].u64_field("height")?, 4);
    assert_eq!(tips[0].str_field("hash")?, hashes[3]);
    assert_eq!(tips[0].u64_field("branchlen")?, 0);

    let stats = node.rpc("getchaintxstats", &json!([]))?;
    assert!(stats.u64_field("txcount")? >= 5, "genesis + 4 coinbases");
    assert_eq!(stats.u64_field("window_final_block_height")?, 4);
    node.stop()
}

/// `gettxoutsetinfo` counts every UTXO and the total supply.
#[test]
fn txoutset_info_counts_utxos() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let _ = mine_bare_blocks(&mut node, 7)?;

    let info = node.rpc("gettxoutsetinfo", &json!([]))?;
    assert_eq!(info.u64_field("height")?, 7);
    // The unspendable genesis coinbase is excluded, as is each block's
    // provably-unspendable OP_RETURN witness-commitment output.
    assert_eq!(info.u64_field("transactions")?, 7);
    assert_eq!(info.u64_field("txouts")?, 7);
    let total = info
        .get("total_amount")
        .and_then(Value::as_f64)
        .ok_or_else(|| Error::Assertion("total_amount missing".into()))?;
    assert!((total - 350.0).abs() < 1e-9, "7 * 50 BTC: {total}");
    node.stop()
}

/// `gettxout` resolves a live outpoint and a spent/unknown one;
/// `gettxoutproof`/`verifytxoutproof` round-trip a merkle proof.
#[test]
fn txout_lookup_and_proof() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let _ = mine_bare_blocks(&mut node, 2)?;
    let coinbase = coinbase_at(&mut node, 1)?;
    let (outpoint, _prevout) = funding_output(&coinbase)?;
    let block_hash = node
        .rpc("getblockhash", &json!([1]))?
        .as_str()
        .ok_or_else(|| Error::Assertion("getblockhash(1)".into()))?
        .to_owned();

    let txout = node.rpc(
        "gettxout",
        &json!([outpoint.txid.to_string(), outpoint.vout]),
    )?;
    assert_eq!(txout.get("coinbase").and_then(Value::as_bool), Some(true));
    let value = txout
        .get("value")
        .and_then(Value::as_f64)
        .ok_or_else(|| Error::Assertion("gettxout value".into()))?;
    assert!((value - 50.0).abs() < 1e-9);
    assert_eq!(txout.u64_field("confirmations")?, 2);

    let missing = node.rpc("gettxout", &json!([outpoint.txid.to_string(), 7u64]))?;
    assert!(missing.is_null(), "unknown vout answers null: {missing}");

    let proof = node.rpc(
        "gettxoutproof",
        &json!([[outpoint.txid.to_string()], block_hash]),
    )?;
    let proof = proof
        .as_str()
        .ok_or_else(|| Error::Assertion("gettxoutproof not hex".into()))?;
    let verified = node.rpc("verifytxoutproof", &json!([proof]))?;
    assert_eq!(
        verified,
        json!([outpoint.txid.to_string()]),
        "proof must verify to the proven txid"
    );
    node.stop()
}

/// `scantxoutset` with an `addr()` descriptor finds the outputs paid to
/// that address by `generatetoaddress`.
#[test]
fn scantxoutset_addr_finds_paid_utxos() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let address = funding_address()?.to_string();
    let result = node.rpc("generatetoaddress", &json!([5, address]))?;
    assert_eq!(
        result.as_array().map(Vec::len),
        Some(5),
        "generatetoaddress must report 5 hashes: {result}"
    );

    let scan = node.rpc(
        "scantxoutset",
        &json!(["start", [format!("addr({address})")]]),
    )?;
    assert_eq!(
        scan.get("success").and_then(Value::as_bool),
        Some(true),
        "scan must succeed: {scan}"
    );
    // Only address-matched outputs count; the OP_RETURN commitment does not.
    assert_eq!(scan.u64_field("txouts")?, 5);
    let unspents = scan
        .get("unspents")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Assertion("unspents missing".into()))?;
    assert_eq!(unspents.len(), 5);
    node.stop()
}

/// Node-introspection and util queries on one node: chain verification, the
/// empty index inventory, pruning refusal, address/descriptor validation,
/// and `uptime` measuring process time rather than call time.
#[test]
fn node_introspection_and_util_queries() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let _ = mine_bare_blocks(&mut node, 3)?;

    assert_eq!(node.rpc("verifychain", &json!([]))?, json!(true));
    // No indexes configured: the manifest reports an empty object.
    assert_eq!(node.rpc("getindexinfo", &json!([]))?, json!({}));

    // Pruning is disabled, so the request is refused rather than honoured.
    let prune = node.rpc_raw(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "pruneblockchain", "params": [1000]
    }))?;
    assert_eq!(prune["error"]["code"], json!(-32603));

    let valid = node.rpc("validateaddress", &json!([funding_address()?.to_string()]))?;
    assert_eq!(valid.get("isvalid"), Some(&json!(true)));
    let bogus = node.rpc("validateaddress", &json!(["not-an-address"]))?;
    assert_eq!(bogus.get("isvalid"), Some(&json!(false)));

    let desc = node.rpc("getdescriptorinfo", &json!(["raw(51)"]))?;
    // The descriptor echo carries the `#checksum` suffix, like Core.
    assert!(
        desc.str_field("descriptor")?.starts_with("raw(51)#"),
        "descriptor: {desc}"
    );
    assert_eq!(desc.str_field("checksum")?, "8lvh9jxk");

    std::thread::sleep(std::time::Duration::from_secs(2));
    let uptime = node.rpc("uptime", &json!([]))?;
    let uptime = uptime
        .as_u64()
        .ok_or_else(|| Error::Assertion(format!("uptime not u64: {uptime}")))?;
    assert!(
        uptime >= 1,
        "uptime must count from node start, got {uptime}"
    );
    node.stop()
}

/// A fresh datadir keeps the coinbase immature: spends of a coinbase
/// under `COINBASE_MATURITY` are refused by mempool admission.
#[test]
fn immature_coinbase_spend_rejected() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let _ = mine_bare_blocks(&mut node, 3)?;
    let coinbase = coinbase_at(&mut node, 1)?;
    let (outpoint, prevout) = funding_output(&coinbase)?;
    let spend = bitcoin_rs_e2e::helpers::spend_anyone(outpoint, &prevout, 1_000);
    let hex = bitcoin_rs_e2e::helpers::tx_hex(&spend);

    let reply = node.rpc_raw(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "sendrawtransaction", "params": [hex]
    }))?;
    // Core's mempool rejection code for a policy/consensus failure.
    assert_eq!(
        reply["error"]["code"],
        json!(-26),
        "immature coinbase spend must be rejected: {reply}"
    );
    assert_eq!(
        reply["error"]["message"],
        json!("consensus-verification-failed"),
        "immature spend must fail script/consensus verification: {reply}"
    );
    node.stop()
}
