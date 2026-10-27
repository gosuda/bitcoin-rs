//! Signed, consensus-validated spend -> retained undo -> BIP352 -> authenticated HTTP.
#![cfg(feature = "silent-payments")]

use std::path::Path;

use anyhow::{Context as _, Result};
use bitcoin::consensus::serialize;
use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::secp256k1::{Scalar, Secp256k1};
use bitcoin::{Amount, OutPoint, PublicKey, ScriptBuf, Sequence, TxOut};
use bitcoin_rs_e2e::helpers::{
    COINBASE_MATURITY, coinbase_at, funding_address, funding_output, mine_blocks_to, raw_spend_to,
    sign_p2pkh_inputs, submit_genesis, tx_hex,
};
use bitcoin_rs_e2e::{Kind, ProcessNode, SpawnOptions};
use serde_json::json;

const OUTPUT_COUNT: usize = 3;
const OUTPUT_KEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

// Independent single-input BIP352 oracle: the fixture's known public key,
// serialized funding outpoint and tagged SHA256, without the node/index codec.
fn expected_tweak(outpoint: OutPoint, prevout: &TxOut) -> Result<String> {
    let key: PublicKey =
        "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f".parse()?;
    assert_eq!(
        prevout.script_pubkey,
        ScriptBuf::new_p2pkh(&key.pubkey_hash())
    );
    let tag = sha256::Hash::hash(b"BIP0352/Inputs");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(tag.as_byte_array());
    bytes.extend_from_slice(tag.as_byte_array());
    bytes.extend_from_slice(&serialize(&outpoint));
    bytes.extend_from_slice(&key.inner.serialize());
    let scalar = Scalar::from_be_bytes(sha256::Hash::hash(&bytes).to_byte_array())?;
    Ok(key
        .inner
        .mul_tweak(&Secp256k1::verification_only(), &scalar)?
        .serialize()
        .to_lower_hex_string())
}

#[test]
fn signed_spend_survives_reorg_and_restart() -> Result<()> {
    let options = SpawnOptions {
        binary: Some(Path::new(env!("CARGO_BIN_EXE_bitcoin-rs"))),
        extra_args: &["--silent-payments"],
        ..SpawnOptions::default()
    };
    let mut node = ProcessNode::spawn_with(Kind::BitcoinRs, &options)?;
    let request = json!({"jsonrpc":"2.0","id":1,"method":"getblocktweaks","params":[101]});
    assert_eq!(
        node.http("POST", "/", &serde_json::to_vec(&request)?, false)?
            .status,
        401
    );
    submit_genesis(&mut node)?;
    let _ = mine_blocks_to(
        &mut node,
        COINBASE_MATURITY,
        &format!("addr({})", funding_address()?),
    )?;
    let (outpoint, prevout) = funding_output(&coinbase_at(&mut node, 1)?)?;
    let expected = expected_tweak(outpoint, &prevout)?;
    let script = ScriptBuf::from_bytes(Vec::from_hex(&format!("5120{OUTPUT_KEY}"))?);
    let mut tx = raw_spend_to(outpoint, &prevout, 10_000, Sequence::MAX, &script);
    // Keep duplicates and dust: candidate completeness is independent of policy.
    tx.output.resize(
        OUTPUT_COUNT,
        TxOut {
            value: Amount::ZERO,
            script_pubkey: script,
        },
    );
    sign_p2pkh_inputs(&mut tx, &[prevout])?;
    let mined = node.rpc("generateblock", &json!(["raw(51)", [tx_hex(&tx)]]))?;
    let hash = mined["hash"].as_str().context("mined hash")?.to_owned();
    assert!(
        node.rpc(
            "gettxout",
            &json!([outpoint.txid.to_string(), outpoint.vout, false])
        )?
        .is_null()
    );

    let result = node.rpc("getblocktweaks", &json!([101]))?;
    assert_eq!(result["height"], 101);
    assert_eq!(result["hash"], hash);
    assert_eq!(result["tip_hash"], hash);
    assert_eq!(result["taproot_active"], true);
    let transactions = result["transactions"].as_array().context("transactions")?;
    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0]["txid"], tx.compute_txid().to_string());
    assert_eq!(transactions[0]["tweak"], expected);
    let outputs = transactions[0]["outputs"].as_array().context("outputs")?;
    assert_eq!(outputs.len(), OUTPUT_COUNT);
    for (vout, output) in outputs.iter().enumerate() {
        assert_eq!(output, &json!({"vout":vout,"output_key":OUTPUT_KEY}));
    }
    node.rpc("invalidateblock", &json!([hash]))?;
    let stale =
        node.rpc_raw(&json!({"jsonrpc":"2.0","id":1,"method":"getblocktweaks","params":[hash]}))?;
    assert_eq!(stale["error"]["code"], -8);
    let replacement = node.rpc("generateblock", &json!(["raw(52)", [tx_hex(&tx)]]))?;
    let replacement_hash = replacement["hash"].as_str().context("replacement hash")?;
    assert_ne!(replacement_hash, hash);
    let replaced = node.rpc("getblocktweaks", &json!({"block":replacement_hash}))?;
    assert_eq!(replaced["hash"], replacement_hash);
    assert_eq!(replaced["tip_hash"], replacement_hash);
    assert_eq!(replaced["transactions"], result["transactions"]);

    let datadir = node.stop_keep_datadir()?;
    let mut node = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &options, datadir)?;
    assert_eq!(node.rpc("getblocktweaks", &json!([101]))?, replaced);
    let datadir = node.stop_keep_datadir()?;
    let mut node = ProcessNode::spawn_in_datadir(
        Kind::BitcoinRs,
        &SpawnOptions {
            extra_args: &[],
            ..options
        },
        datadir,
    )?;
    assert_eq!(node.rpc_raw(&request)?["error"]["code"], -32603);
    node.stop()?;
    Ok(())
}
