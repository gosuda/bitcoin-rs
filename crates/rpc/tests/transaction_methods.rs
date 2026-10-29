#![allow(clippy::expect_used)]

extern crate alloc;

use alloc::sync::Arc;

use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin_rs_mempool::{AdmissionOrigin, MempoolEntry};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    consensus_bytes, deserialize,
};
use bitcoin_rs_rpc::context::Context;
use bitcoin_rs_rpc::{Handler, RpcError};
use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

const P2WPKH_SCRIPT_HEX: &str = "00141111111111111111111111111111111111111111";

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    Vec::from_hex(hex).map_err(|error| error.to_string())
}

fn is_op_return(script: &[u8]) -> bool {
    script.first() == Some(&0x6a_u8)
}

fn make_tx(prevout: OutPoint, output_value: u64, script: Vec<u8>) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: prevout,
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xFFFF_FFFE),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: script.into(),
        }],
    }
}

fn fund_utxo(ctx: &Context, txid_byte: u8, value: u64) -> OutPoint {
    let txid = Hash256::from_le_bytes(&[txid_byte; 32]);
    let outpoint = OutPoint::new(Txid(txid), 0);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        outpoint,
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: vec![0x51].into(),
        },
        false,
        1,
    ));
    bitcoin_rs_utxo::contract::commit_block_changes(
        &ctx.chain.utxo.fixture_set(),
        &changes,
        &Hash256::from_le_bytes(&[0xaa; 32]),
    )
    .expect("commit_block");
    outpoint
}

#[test]
fn sendrawtransaction_admits_standard_tx_to_mempool() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
    let prevout = fund_utxo(&ctx, 0x42, 10_000);
    let tx = make_tx(prevout, 9_000, script);
    let raw = consensus_bytes(&tx).to_lower_hex_string();
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch("sendrawtransaction", &json!([raw.as_str()]))?;
    let returned_txid = result.as_str().ok_or("expected txid string")?;
    assert_eq!(returned_txid, tx.txid().to_string());

    assert!(
        ctx.mempool.gateway.read().contains_txid(&tx.txid()),
        "tx was not admitted to mempool"
    );
    Ok(())
}

#[test]
fn sendrawtransaction_rejects_missing_inputs() {
    let ctx = Arc::new(Context::new());
    let script = hex_decode(P2WPKH_SCRIPT_HEX).expect("script hex");
    let prevout = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x99; 32])), 0);
    let tx = make_tx(prevout, 9_000, script);
    let raw = consensus_bytes(&tx).to_lower_hex_string();
    let handler = Handler::new(Arc::clone(&ctx));

    let err = handler
        .dispatch("sendrawtransaction", &json!([raw.as_str()]))
        .expect_err("missing-inputs tx should be rejected");
    assert_eq!(err.code(), -25);
}

#[test]
fn sendrawtransaction_idempotent_for_already_in_mempool() -> Result<(), Box<dyn std::error::Error>>
{
    let ctx = Arc::new(Context::new());
    let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
    let prevout = fund_utxo(&ctx, 0x43, 10_000);
    let tx = make_tx(prevout, 9_000, script);
    let txid = tx.txid();

    let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 1, 0);
    ctx.mempool.gateway.pool().write().insert_entry(entry)?;

    let raw = consensus_bytes(&tx).to_lower_hex_string();
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch("sendrawtransaction", &json!([raw.as_str()]))?;
    assert_eq!(result.as_str(), Some(txid.to_string().as_str()));
    Ok(())
}

#[test]
fn sendrawtransaction_readmits_a_transaction_evicted_from_the_mempool()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
    let prevout = fund_utxo(&ctx, 0x44, 10_000);
    let tx = make_tx(prevout, 9_000, script);
    let txid = tx.txid();
    let raw = consensus_bytes(&tx).to_lower_hex_string();
    let handler = Handler::new(Arc::clone(&ctx));

    handler.dispatch("sendrawtransaction", &json!([raw.as_str()]))?;
    assert!(
        ctx.mempool.gateway.read().contains_txid(&txid),
        "first admission"
    );

    let removed = ctx
        .mempool
        .gateway
        .evict_below_fee_rate(AdmissionOrigin::Rpc, u64::MAX);
    assert!(
        !removed.changes.is_empty(),
        "the eviction must have removed the entry"
    );
    assert!(!ctx.mempool.gateway.read().contains_txid(&txid));

    let result = handler.dispatch("sendrawtransaction", &json!([raw.as_str()]))?;
    assert_eq!(result.as_str(), Some(txid.to_string().as_str()));
    assert!(
        ctx.mempool.gateway.read().contains_txid(&txid),
        "resubmitting an evicted transaction must admit it again, not report success silently"
    );
    Ok(())
}

fn funded_standard_tx(
    txid_byte: u8,
    funded: u64,
    output: u64,
) -> Result<(Arc<Context>, Tx, String), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
    let prevout = fund_utxo(&ctx, txid_byte, funded);
    let tx = make_tx(prevout, output, script);
    let raw = consensus_bytes(&tx).to_lower_hex_string();
    Ok((ctx, tx, raw))
}

#[test]
fn sendrawtransaction_admits_the_lnd_wallet_broadcast_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let (ctx, tx, raw) = funded_standard_tx(0x50, 10_000, 9_000)?;
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch("sendrawtransaction", &json!([raw.as_str(), false]))?;

    assert_eq!(result.as_str(), Some(tx.txid().to_string().as_str()));
    assert!(
        ctx.mempool.gateway.read().contains_txid(&tx.txid()),
        "the wallet transaction must be in the mempool, not only acknowledged"
    );
    Ok(())
}

#[test]
fn the_legacy_allowhighfees_false_keeps_the_default_fee_ceiling()
-> Result<(), Box<dyn std::error::Error>> {
    let (ctx, tx, raw) = funded_standard_tx(0x51, 100_000_000, 1_000_000)?;
    let handler = Handler::new(Arc::clone(&ctx));

    let refused = handler
        .dispatch("sendrawtransaction", &json!([raw.as_str(), false]))
        .expect_err("allowhighfees=false keeps the default fee ceiling");
    assert_eq!(refused.code(), RpcError::INVALID_PARAMS, "{refused:?}");
    assert!(!ctx.mempool.gateway.read().contains_txid(&tx.txid()));

    let typed = handler
        .dispatch("sendrawtransaction", &json!([raw.as_str(), true]))
        .expect_err("allowhighfees=true is not accepted");
    assert_eq!(typed.code(), -3, "{typed:?}");
    assert!(!ctx.mempool.gateway.read().contains_txid(&tx.txid()));
    Ok(())
}

/// Omitted, null, numeric and numeric-string ceilings keep Core's `maxfeerate`
/// meaning, and everything that is neither an amount nor the legacy boolean
/// is still refused before any admission.
#[test]
fn sendrawtransaction_fee_argument_keeps_core_amount_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    for (index, fee) in [json!(null), json!(0.1), json!("0.1"), json!(0)]
        .into_iter()
        .enumerate()
    {
        let byte = 0x60 + u8::try_from(index)?;
        let (ctx, tx, raw) = funded_standard_tx(byte, 10_000, 9_000)?;
        let handler = Handler::new(Arc::clone(&ctx));

        let sent = handler.dispatch("sendrawtransaction", &json!([raw.as_str(), fee]))?;

        assert_eq!(
            sent.as_str(),
            Some(tx.txid().to_string().as_str()),
            "{fee:?}"
        );
        assert!(ctx.mempool.gateway.read().contains_txid(&tx.txid()));
    }

    let core_type_error = -3;
    for (index, (fee, code)) in [
        (json!([false]), Some(core_type_error)),
        (json!({"maxfeerate": false}), Some(core_type_error)),
        (json!(-0.1), Some(RpcError::INVALID_PARAMS)),
        (json!(1.0), Some(RpcError::INVALID_PARAMS)),
        (json!("false"), None),
    ]
    .into_iter()
    .enumerate()
    {
        let byte = 0x70 + u8::try_from(index)?;
        let (ctx, tx, raw) = funded_standard_tx(byte, 10_000, 9_000)?;
        let handler = Handler::new(Arc::clone(&ctx));

        let refused = handler
            .dispatch("sendrawtransaction", &json!([raw.as_str(), fee]))
            .expect_err("a fee argument that is not an amount stays refused");

        if let Some(code) = code {
            assert_eq!(refused.code(), code, "{fee:?}: {refused:?}");
        }
        assert!(
            !ctx.mempool.gateway.read().contains_txid(&tx.txid()),
            "{fee:?} must not admit anything"
        );
    }
    Ok(())
}

#[test]
fn testmempoolaccept_still_refuses_a_boolean_maxfeerate() -> Result<(), Box<dyn std::error::Error>>
{
    let (ctx, _tx, raw) = funded_standard_tx(0x80, 10_000, 9_000)?;
    let handler = Handler::new(Arc::clone(&ctx));

    let refused = handler
        .dispatch("testmempoolaccept", &json!([[raw.as_str()], false]))
        .expect_err("testmempoolaccept keeps Core's amount-only maxfeerate");

    assert_eq!(refused.code(), -3, "{refused:?}");
    Ok(())
}

#[test]
fn testmempoolaccept_reports_allowed_for_valid_tx() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
    let prevout = fund_utxo(&ctx, 0x44, 10_000);
    let tx = make_tx(prevout, 9_000, script);
    let raw = consensus_bytes(&tx).to_lower_hex_string();
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch("testmempoolaccept", &json!([[raw.as_str()]]))?;
    let rows = result.as_array().ok_or("expected array")?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("allowed").as_bool(), Some(true));
    assert!(
        rows[0].get("reject-reason").is_none(),
        "no reject-reason for allowed tx"
    );
    Ok(())
}

#[test]
fn testmempoolaccept_reports_reject_for_already_in_mempool()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
    let prevout = fund_utxo(&ctx, 0x45, 10_000);
    let tx = make_tx(prevout, 9_000, script);
    let txid = tx.txid();

    let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 1, 0);
    ctx.mempool.gateway.pool().write().insert_entry(entry)?;

    let raw = consensus_bytes(&tx).to_lower_hex_string();
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch("testmempoolaccept", &json!([[raw.as_str()]]))?;
    let rows = result.as_array().ok_or("expected array")?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("allowed").as_bool(), Some(false));
    let reason = rows[0]
        .get("reject-reason")
        .and_then(JsonValueTrait::as_str)
        .ok_or("expected reject-reason")?;
    assert!(
        reason.contains("already-in-mempool"),
        "reject-reason should mention already-in-mempool: {reason}"
    );
    assert_eq!(
        rows[0].get("txid").as_str(),
        Some(txid.to_string().as_str())
    );
    Ok(())
}

#[test]
fn testmempoolaccept_reports_reject_for_missing_inputs() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = hex_decode(P2WPKH_SCRIPT_HEX).expect("script hex");
    let prevout = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x77; 32])), 0);
    let tx = make_tx(prevout, 9_000, script);
    let raw = consensus_bytes(&tx).to_lower_hex_string();
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch("testmempoolaccept", &json!([[raw.as_str()]]))?;
    let rows = result.as_array().ok_or("expected array")?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("allowed").as_bool(), Some(false));
    let reason = rows[0]
        .get("reject-reason")
        .and_then(JsonValueTrait::as_str)
        .ok_or("expected reject-reason")?;
    assert!(
        reason.contains("missing-inputs"),
        "reject-reason should mention missing-inputs: {reason}"
    );
    Ok(())
}

#[test]
fn gettxout_returns_unconfirmed_output_from_mempool() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
    let tx = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0xaa; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xFFFF_FFFE),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(7_500),
            script_pubkey: script.into(),
        }],
    };
    let txid = tx.txid();
    let entry = MempoolEntry::new(Arc::new(tx), 100, 500, 1, 1, 0);
    ctx.mempool.gateway.pool().write().insert_entry(entry)?;

    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler.dispatch("gettxout", &json!([txid.to_string(), 0_u64]))?;

    assert!(!result.is_null(), "expected non-null for mempool output");
    assert_eq!(result.get("confirmations").as_u64(), Some(0));
    assert_eq!(result.get("coinbase").as_bool(), Some(false));
    Ok(())
}

#[test]
fn gettxout_include_mempool_false_skips_mempool() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
    let tx = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0xbb; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xFFFF_FFFE),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(7_500),
            script_pubkey: script.into(),
        }],
    };
    let txid = tx.txid();
    let entry = MempoolEntry::new(Arc::new(tx), 100, 500, 1, 1, 0);
    ctx.mempool.gateway.pool().write().insert_entry(entry)?;

    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler.dispatch("gettxout", &json!([txid.to_string(), 0_u64, false]))?;
    assert!(result.is_null(), "expected null when mempool is excluded");
    Ok(())
}

#[test]
fn gettxout_returns_null_for_outpoint_spent_in_mempool() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = hex_decode(P2WPKH_SCRIPT_HEX)?;

    let prevout = fund_utxo(&ctx, 0x55, 10_000);

    let spending_tx = make_tx(prevout, 9_000, script);
    let entry = MempoolEntry::new(Arc::new(spending_tx), 100, 1_000, 1, 1, 0);
    ctx.mempool.gateway.pool().write().insert_entry(entry)?;

    let spent_txid = prevout.txid;
    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler.dispatch("gettxout", &json!([spent_txid.to_string(), 0_u64]))?;
    assert!(
        result.is_null(),
        "expected null for outpoint spent in mempool"
    );
    Ok(())
}

#[test]
fn createrawtransaction_builds_valid_hex_tx() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));

    let inputs = json!([{
        "txid": "0000000000000000000000000000000000000000000000000000000000000001",
        "vout": 0
    }]);
    let outputs = json!({
        "1BoatSLRHtKNngkdXEeobR76b53LETtpyT": 0.001
    });

    let result = handler.dispatch("createrawtransaction", &json!([inputs, outputs]))?;

    let hex = result
        .as_str()
        .ok_or("createrawtransaction should return a hex string")?;
    let bytes = hex_decode(hex)?;
    let tx: Tx = deserialize(&bytes)?;
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 1);
    let previous_output = tx.inputs[0].previous_output;
    let (input_txid, input_vout) = (previous_output.txid, previous_output.vout);
    assert_eq!(
        input_txid.to_string(),
        "0000000000000000000000000000000000000000000000000000000000000001"
    );
    assert_eq!(input_vout, 0);
    Ok(())
}

#[test]
fn createrawtransaction_creates_op_return_data_output() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = Context::new();
    ctx.chain.chain_network = bitcoin_rs_primitives::Network::Regtest;
    let handler = Handler::new(Arc::new(ctx));

    let inputs = json!([{
        "txid": "0000000000000000000000000000000000000000000000000000000000000002",
        "vout": 1
    }]);
    let outputs = json!({
        "data": "48656c6c6f"
    });

    let result = handler.dispatch(
        "createrawtransaction",
        &json!([inputs, outputs, 0_u64, true]),
    )?;

    let hex = result
        .as_str()
        .ok_or("createrawtransaction should return a hex string")?;
    let bytes = hex_decode(hex)?;
    let tx: Tx = deserialize(&bytes)?;
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 1);
    assert!(is_op_return(&tx.outputs[0].script_pubkey));
    assert_eq!(tx.outputs[0].value, 0);
    assert!(tx.inputs[0].sequence < 0xFFFF_FFFE);
    Ok(())
}

#[test]
fn createrawtransaction_rejects_duplicate_input() {
    let mut ctx = Context::new();
    ctx.chain.chain_network = bitcoin_rs_primitives::Network::Regtest;
    let handler = Handler::new(Arc::new(ctx));

    let inputs = json!([
        {"txid": "0000000000000000000000000000000000000000000000000000000000000003", "vout": 0},
        {"txid": "0000000000000000000000000000000000000000000000000000000000000003", "vout": 0}
    ]);
    let outputs = json!({"data": "00"});

    let err = handler
        .dispatch("createrawtransaction", &json!([inputs, outputs]))
        .expect_err("duplicate input should be rejected");
    assert_eq!(err.code(), RpcError::INVALID_PARAMS);
}
