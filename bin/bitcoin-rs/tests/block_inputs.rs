//! Certified input reads must not depend on a speculative verbose JSON estimate.
#![cfg(feature = "silent-payments")]

use std::path::Path;

use anyhow::{Context as _, Result};
use bitcoin::consensus::serialize;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::{Amount, ScriptBuf, Sequence, TxOut};
use bitcoin_rs_e2e::helpers::{
    COINBASE_MATURITY, coinbase_at, funding_address, funding_output, mine_blocks_to, raw_spend_to,
    sign_p2pkh_inputs, submit_genesis, tx_hex,
};
use bitcoin_rs_e2e::{Kind, ProcessNode, SpawnOptions};
use serde_json::json;

#[test]
fn taproot_heavy_block_has_complete_certified_inputs_and_candidates() -> Result<()> {
    const OUTPUTS: usize = 12_500;
    const KEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let mut node = ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            binary: Some(Path::new(env!("CARGO_BIN_EXE_bitcoin-rs"))),
            extra_args: &["--rest=true", "--silent-payments"],
            ..SpawnOptions::default()
        },
    )?;
    submit_genesis(&mut node)?;
    let _ = mine_blocks_to(
        &mut node,
        COINBASE_MATURITY,
        &format!("addr({})", funding_address()?),
    )?;
    let (outpoint, prevout) = funding_output(&coinbase_at(&mut node, 1)?)?;
    let script = ScriptBuf::from_bytes(Vec::from_hex(&format!("5120{KEY}"))?);
    let mut tx = raw_spend_to(outpoint, &prevout, 10_000, Sequence::MAX, &script);
    // These outputs alone exceeded the old source estimate:
    // 12,500 * (1,024 + 2 * 34 * 64) > 64 MiB, before counting body/input bytes.
    tx.output.resize(
        OUTPUTS,
        TxOut {
            value: Amount::ZERO,
            script_pubkey: script,
        },
    );
    sign_p2pkh_inputs(&mut tx, std::slice::from_ref(&prevout))?;
    let mined = node.rpc("generateblock", &json!(["raw(51)", [tx_hex(&tx)]]))?;
    let hash = mined["hash"].as_str().context("mined hash")?;

    // The real getblock adapter reads Chainstate::block_spends, including its
    // durable receipt, native undo and historical prevout (now spent in live UTXO).
    let verbose = node.rpc("getblock", &json!([hash, 3]))?;
    assert_eq!(verbose["hash"], hash);
    assert!(verbose["weight"].as_u64().context("weight")? <= 4_000_000);
    assert_eq!(
        verbose["tx"][1]["vout"].as_array().context("vout")?.len(),
        OUTPUTS
    );
    let coin = &verbose["tx"][1]["vin"][0]["prevout"];
    assert_eq!(coin["height"], 1);
    assert_eq!(coin["generated"], true);
    assert_eq!(
        coin["scriptPubKey"]["hex"],
        prevout.script_pubkey.as_bytes().to_lower_hex_string()
    );
    assert_eq!(verbose["tx"][1]["fee"].as_f64(), Some(0.0001));

    let response = node.http_get(&format!("/rest/spenttxouts/{hash}.bin"))?;
    assert_eq!(response.status, 200);
    // CompactSize row count, empty coinbase row, then one spent prevout.
    let mut expected = vec![2, 0, 1];
    expected.extend_from_slice(&serialize(&prevout));
    assert_eq!(response.body, expected);

    let tweaks = node.rpc("getblocktweaks", &json!([hash]))?;
    assert_eq!(tweaks["hash"], hash);
    let transactions = tweaks["transactions"].as_array().context("transactions")?;
    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0]["txid"], tx.compute_txid().to_string());
    let outputs = transactions[0]["outputs"].as_array().context("outputs")?;
    assert_eq!(outputs.len(), OUTPUTS);
    for (vout, output) in outputs.iter().enumerate() {
        assert_eq!(output, &json!({"vout":vout,"output_key":KEY}));
    }
    node.stop()?;
    Ok(())
}
