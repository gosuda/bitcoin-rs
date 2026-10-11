//! Retained undo across public RPC/REST, compared with pinned unmodified Core.

use std::io::Cursor;
use std::time::Duration;

use bitcoin::consensus::{Decodable as _, encode::serialize_hex};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, VarInt, Witness};
use bitcoin_rs_e2e::differential::{CommonFunds, compare_reply, mine_common_chain};
use bitcoin_rs_e2e::helpers::{funding_address, sign_p2pkh_inputs, signed_spend};
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, SpawnOptions, ValueExt};
use serde_json::{Value, json};

fn indexed_options() -> SpawnOptions<'static> {
    SpawnOptions {
        extra_args: &["--rest=true", "--txindex=true"],
        ..SpawnOptions::default()
    }
}

/// The complete object protects unsigned wire versions and all optional chain
/// fields while exercising the same read consumer in each availability state.
fn compare_raw_transaction(
    core: &mut ProcessNode,
    node: &mut ProcessNode,
    txid: &str,
    block: Option<&str>,
) -> Result<Value> {
    let params = if let Some(block) = block {
        json!([txid, true, block])
    } else {
        json!([txid, true])
    };
    let reference = core.rpc("getrawtransaction", &params)?;
    let native = node.rpc("getrawtransaction", &params)?;
    compare_reply("verbose raw transaction", &reference, &native)?;
    Ok(native)
}

fn compare_raw_lookup_sources(
    core: &mut ProcessNode,
    node: &mut ProcessNode,
    funds: &CommonFunds,
    txid: &str,
    block: &str,
) -> Result<()> {
    let explicit = compare_raw_transaction(core, node, txid, Some(block))?;
    assert_eq!(explicit["version"], u32::MAX);
    assert_eq!(explicit["in_active_chain"], true);
    for process in [&mut *core, &mut *node] {
        process.wait_for(
            "txindex reaches high-version block",
            Duration::from_secs(15),
            |process| {
                let info = process.rpc("getindexinfo", &json!([]))?;
                Ok((info["txindex"]["best_block_height"].as_u64() == Some(103)
                    && info["txindex"]["synced"] == true)
                    .then_some(()))
            },
        )?;
    }
    let indexed = compare_raw_transaction(core, node, txid, None)?;
    assert!(indexed.get("in_active_chain").is_none());
    assert_eq!(indexed["version"], u32::MAX);
    // Standard version 2 can enter both mempools without a policy override.
    // The high-bit version above is covered through actual block admission.
    let (outpoint, prevout) = funds.confirmed_output(2)?;
    let mempool = signed_spend(outpoint, &prevout, 1000, Sequence::MAX)?;
    let mempool_id = mempool.compute_txid().to_string();
    for process in [&mut *core, &mut *node] {
        process.rpc("sendrawtransaction", &json!([serialize_hex(&mempool)]))?;
    }
    let unconfirmed = compare_raw_transaction(core, node, &mempool_id, None)?;
    for field in [
        "blockhash",
        "confirmations",
        "time",
        "blocktime",
        "in_active_chain",
    ] {
        assert!(
            unconfirmed.get(field).is_none(),
            "mempool field {field} must be absent"
        );
    }
    Ok(())
}

fn submit_common(
    core: &mut ProcessNode,
    node: &mut ProcessNode,
    transactions: &[String],
) -> Result<String> {
    let candidate = core.rpc(
        "generateblock",
        &json!([funding_address()?.to_string(), transactions, false]),
    )?;
    let hex = candidate.str_field("hex")?;
    let accepted = core.rpc("submitblock", &json!([hex]))?;
    assert!(
        accepted.is_null(),
        "Core rejected its candidate: {accepted}"
    );
    let accepted = node.rpc("submitblock", &json!([hex]))?;
    assert!(
        accepted.is_null(),
        "native rejection of Core block: {accepted}"
    );
    Ok(candidate.str_field("hash")?.to_owned())
}

fn compare_formats(core: &mut ProcessNode, node: &mut ProcessNode, hash: &str) -> Result<Value> {
    for verbosity in [2, 3] {
        let reference = core.rpc("getblock", &json!([hash, verbosity]))?;
        let native = node.rpc("getblock", &json!([hash, verbosity]))?;
        compare_reply("verbose block with retained undo", &reference, &native)?;
        compare_reply(
            "named verbose block",
            &reference,
            &node.rpc("getblock", &json!({"blockhash":hash,"verbosity":verbosity}))?,
        )?;
        assert!(native["tx"][0].get("fee").is_none());
        assert!(native["tx"][0]["vin"][0].get("prevout").is_none());
        if verbosity == 2 {
            for tx in native["tx"]
                .as_array()
                .ok_or_else(|| Error::Protocol("tx array missing".into()))?
            {
                for input in tx["vin"]
                    .as_array()
                    .ok_or_else(|| Error::Protocol("vin array missing".into()))?
                {
                    assert!(input.get("prevout").is_none());
                }
            }
        }
    }
    let path = format!("/rest/spenttxouts/{hash}");
    let reference_json = core.http_get(&format!("{path}.json"))?;
    let native_json = node.http_get(&format!("{path}.json"))?;
    assert_eq!(reference_json.status, 200);
    assert_eq!(native_json.status, 200);
    compare_reply(
        "spent outputs JSON",
        &reference_json.json()?,
        &native_json.json()?,
    )?;
    let binary = node.http_get(&format!("{path}.bin"))?;
    let reference = core.http_get(&format!("{path}.bin"))?;
    assert_eq!(binary.status, 200);
    assert_eq!(binary.body, reference.body);
    assert_eq!(
        node.http_get(&format!("{path}.hex"))?.body,
        core.http_get(&format!("{path}.hex"))?.body
    );
    // Independently decode ordinary Bitcoin TxOuts, not the native undo codec.
    let rows = native_json.json()?;
    let rows = rows
        .as_array()
        .ok_or_else(|| Error::Protocol("spent array missing".into()))?;
    let mut cursor = Cursor::new(&binary.body);
    let count = VarInt::consensus_decode(&mut cursor)
        .map_err(|e| Error::Protocol(e.to_string()))?
        .0;
    assert_eq!(
        usize::try_from(count).map_err(|e| Error::Protocol(e.to_string()))?,
        rows.len()
    );
    for row in rows {
        let row = row
            .as_array()
            .ok_or_else(|| Error::Protocol("spent row missing".into()))?;
        let inputs = VarInt::consensus_decode(&mut cursor)
            .map_err(|e| Error::Protocol(e.to_string()))?
            .0;
        assert_eq!(
            usize::try_from(inputs).map_err(|e| Error::Protocol(e.to_string()))?,
            row.len()
        );
        for coin in row {
            let output = bitcoin::TxOut::consensus_decode(&mut cursor)
                .map_err(|e| Error::Protocol(e.to_string()))?;
            assert_eq!(
                output.script_pubkey.to_hex_string(),
                coin["scriptPubKey"]["hex"]
            );
            assert_eq!(json!(output.value.to_btc()), coin["value"]);
        }
    }
    assert_eq!(
        cursor.position(),
        u64::try_from(binary.body.len()).map_err(|e| Error::Protocol(e.to_string()))?
    );
    node.rpc("getblock", &json!([hash, 3]))
}

#[test]
fn undo_formats_same_block_inputs_stale_extent_and_restart() -> Result<()> {
    let mut core = ProcessNode::spawn_with(
        Kind::Core,
        &SpawnOptions {
            extra_args: &["-rest=1", "-txindex=1"],
            ..SpawnOptions::default()
        },
    )?;
    let mut node = ProcessNode::spawn_with(Kind::BitcoinRs, &indexed_options())?;
    let funds = mine_common_chain(&mut core, &mut node, 102)?;
    let mut parent = funds.signed_spend(1000, Sequence::MAX)?;
    parent.version = bitcoin::transaction::Version(-1);
    let (_, first) = funds.confirmed_output(0)?;
    let (second_outpoint, second) = funds.confirmed_output(1)?;
    parent.input.push(TxIn {
        previous_output: second_outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    });
    parent.output[0].value = Amount::from_sat(first.value.to_sat() + second.value.to_sat() - 1000);
    sign_p2pkh_inputs(&mut parent, &[first, second])?;
    let child = signed_spend(
        OutPoint::new(parent.compute_txid(), 0),
        &parent.output[0],
        2000,
        Sequence::MAX,
    )?;
    let block = submit_common(
        &mut core,
        &mut node,
        &[serialize_hex(&parent), serialize_hex(&child)],
    )?;
    let txid = parent.compute_txid().to_string();
    compare_raw_lookup_sources(&mut core, &mut node, &funds, &txid, &block)?;
    let result = compare_formats(&mut core, &mut node, &block)?;
    assert_eq!(result["tx"][1]["version"], u32::MAX);
    assert_eq!(
        result["version"],
        core.rpc("getblockheader", &json!([block]))?["version"]
    );
    compare_rest_errors(&mut core, &mut node, &block)?;
    assert_eq!(result["tx"][1]["vin"][0]["prevout"]["height"], 1);
    assert_eq!(result["tx"][1]["vin"][1]["prevout"]["height"], 2);
    assert_eq!(result["tx"][2]["vin"][0]["prevout"]["height"], 103);
    assert_eq!(result["tx"][2]["vin"][0]["prevout"]["generated"], false);
    for height in [0, 1] {
        let hash = core.rpc("getblockhash", &json!([height]))?;
        compare_formats(
            &mut core,
            &mut node,
            hash.as_str()
                .ok_or_else(|| Error::Protocol("hash missing".into()))?,
        )?;
    }
    for process in [&mut core, &mut node] {
        process.rpc("invalidateblock", &json!([block]))?;
    }
    let stale_tx = compare_raw_transaction(&mut core, &mut node, &txid, Some(&block))?;
    assert_eq!(stale_tx["in_active_chain"], false);
    assert_eq!(stale_tx["confirmations"], 0);
    assert!(stale_tx.get("time").is_none());
    assert!(stale_tx.get("blocktime").is_none());
    let stale = compare_formats(&mut core, &mut node, &block)?;
    assert_eq!(stale["confirmations"], -1);
    assert!(stale.get("nextblockhash").is_none());
    submit_common(&mut core, &mut node, &[])?;
    let replacement = submit_common(&mut core, &mut node, &[])?;
    // Exact declared deviation: a later receipt no longer certifies the old
    // branch. Its stored rows must not be promoted to trusted history.
    let native = node.rpc("getblock", &json!([block, 3]))?;
    let reference = core.rpc("getblock", &json!([block, 3]))?;
    assert_eq!(native["confirmations"], reference["confirmations"]);
    assert!(native.get("nextblockhash").is_none());
    assert!(reference.get("nextblockhash").is_none());
    assert!(native["tx"][1]["vin"][0].get("prevout").is_none());
    assert!(native["tx"][1].get("fee").is_none());
    assert_eq!(
        node.http_get(&format!("/rest/spenttxouts/{block}.json"))?
            .status,
        404
    );
    assert_eq!(
        core.http_get(&format!("/rest/spenttxouts/{block}.json"))?
            .status,
        200
    );
    let datadir = node.stop_keep_datadir()?;
    let mut node = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &indexed_options(), datadir)?;
    compare_formats(&mut core, &mut node, &replacement)?;
    node.stop()?;
    core.stop()
}

#[test]
fn pruned_undo_is_unavailable_and_retained_undo_survives_restart() -> Result<()> {
    // Core's ordinary debug option rotates 64 KiB block files and permits
    // pruning after height 100; the binary itself is the pinned release.
    let mut core = ProcessNode::spawn_with(
        Kind::Core,
        &SpawnOptions {
            extra_args: &["-rest=1", "-prune=1", "-fastprune=1"],
            ..SpawnOptions::default()
        },
    )?;
    let opts = SpawnOptions {
        extra_args: &["--rest=true", "--prune-target-mb=1"],
        ..SpawnOptions::default()
    };
    let mut node = ProcessNode::spawn_with(Kind::BitcoinRs, &opts)?;
    for _ in 0..8 {
        mine_common_chain(&mut core, &mut node, 100)?;
    }
    let old = core.rpc("getblockhash", &json!([1]))?;
    let genesis = core.rpc("getblockhash", &json!([0]))?;
    let tip = core.rpc("getbestblockhash", &json!([]))?;
    // A clean checkpoint establishes the native pruner's recovery floor.
    let datadir = node.stop_keep_datadir()?;
    let mut node = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &opts, datadir)?;
    for process in [&mut core, &mut node] {
        process.rpc("pruneblockchain", &json!([400]))?;
        let reply = process
            .rpc_raw(&json!({"jsonrpc":"2.0", "id":1, "method":"getblock", "params":[old,3]}))?;
        assert_eq!(reply["error"]["code"], -1);
        assert_eq!(
            reply["error"]["message"],
            "Block not available (pruned data)"
        );
        let genesis_block = process.rpc_raw(
            &json!({"jsonrpc":"2.0", "id":1, "method":"getblock", "params":[genesis,3]}),
        )?;
        assert_eq!(genesis_block["error"]["code"], -1);
        let genesis_hash = genesis
            .as_str()
            .ok_or_else(|| Error::Protocol("genesis hash missing".into()))?;
        let empty = process.http_get(&format!("/rest/spenttxouts/{genesis_hash}.bin"))?;
        assert_eq!(empty.status, 200);
        assert_eq!(empty.body, vec![1, 0]);
        let hash = old
            .as_str()
            .ok_or_else(|| Error::Protocol("hash missing".into()))?;
        assert_eq!(
            process
                .http_get(&format!("/rest/spenttxouts/{hash}.bin"))?
                .status,
            404
        );
    }
    compare_formats(
        &mut core,
        &mut node,
        tip.as_str()
            .ok_or_else(|| Error::Protocol("tip missing".into()))?,
    )?;
    let datadir = node.stop_keep_datadir()?;
    let mut node = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &opts, datadir)?;
    compare_formats(
        &mut core,
        &mut node,
        tip.as_str()
            .ok_or_else(|| Error::Protocol("tip missing".into()))?,
    )?;
    node.stop()?;
    core.stop()
}

fn compare_rest_errors(core: &mut ProcessNode, node: &mut ProcessNode, known: &str) -> Result<()> {
    for suffix in [
        "bad.json".to_owned(),
        format!("{}.json", "00".repeat(32)),
        format!("{known}/extra.json"),
        format!("{known}.txt"),
        known.to_owned(),
    ] {
        let path = format!("/rest/spenttxouts/{suffix}");
        let reference = core.http_get(&path)?;
        let native = node.http_get(&path)?;
        assert_eq!(reference.status, native.status);
        let reference =
            std::str::from_utf8(&reference.body).map_err(|e| Error::Protocol(e.to_string()))?;
        let native =
            std::str::from_utf8(&native.body).map_err(|e| Error::Protocol(e.to_string()))?;
        assert_eq!(reference.trim(), native.trim());
    }
    Ok(())
}
