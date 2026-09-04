//! Behavioral tests for transaction RPC methods: real mempool admission,
//! mempool-aware gettxout, createrawtransaction, and testmempoolaccept
//! evaluation.

// A failed fixture invariant is a test failure, and panicking reports it with
// the offending call site. `expect` is deliberate.
#![allow(clippy::expect_used)]

extern crate alloc;

use alloc::sync::Arc;

use bitcoin_rs_mempool::MempoolEntry;
use bitcoin_rs_primitives::{
    Hash256, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes, deserialize,
};
use bitcoin_rs_rpc::context::Context;
use bitcoin_rs_rpc::{Handler, RpcError};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

/// A standard P2WPKH script paid to a known key.
const P2WPKH_SCRIPT_HEX: &str = "00141111111111111111111111111111111111111111";

/// Encodes `bytes` as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// Decodes hexadecimal into bytes, rejecting odd length and invalid digits.
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    fn nibble(byte: u8) -> Result<u8, String> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err(format!("invalid hex digit: {}", char::from(byte))),
        }
    }
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(format!("odd-length hex input: {hex}"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = nibble(pair[0])?;
        let low = nibble(pair[1])?;
        out.push(high << 4 | low);
    }
    Ok(out)
}

/// Returns `true` when the script starts with `OP_RETURN` (0x6a).
fn is_op_return(script: &[u8]) -> bool {
    script.first() == Some(&0x6a_u8)
}

fn make_tx(prevout: OutPoint, output_value: u64, script: Vec<u8>) -> Tx {
    Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: prevout,
            script_sig: Vec::new(),
            sequence: 0xFFFF_FFFE,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: output_value,
            script_pubkey: script,
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
            value,
            // OP_TRUE: an anyone-can-spend prevout, so the empty scriptSigs
            // these fixtures build satisfy script verification.
            script_pubkey: vec![0x51],
        },
        false,
        1,
    ));
    ctx.utxo
        .commit_block(&changes, &Hash256::from_le_bytes(&[0xaa; 32]))
        .expect("commit_block");
    outpoint
}

// ---------------------------------------------------------------------------
// sendrawtransaction — real mempool admission
// ---------------------------------------------------------------------------

#[test]
fn sendrawtransaction_admits_standard_tx_to_mempool() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
    let prevout = fund_utxo(&ctx, 0x42, 10_000);
    // Spend 10 000 sats, send 9 000 → fee 1 000 sats.
    let tx = make_tx(prevout, 9_000, script);
    let raw = hex_encode(&consensus_bytes(&tx));
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch("sendrawtransaction", &json!([raw.as_str()]))?;
    let returned_txid = result.as_str().ok_or("expected txid string")?;
    assert_eq!(returned_txid, tx.txid().to_string());

    // The tx must be in the mempool.
    assert!(
        ctx.mempool.read().contains_txid(&tx.txid()),
        "tx was not admitted to mempool"
    );
    Ok(())
}

#[test]
fn sendrawtransaction_rejects_missing_inputs() {
    let ctx = Arc::new(Context::new());
    let script = hex_decode(P2WPKH_SCRIPT_HEX).expect("script hex");
    // Reference an outpoint that does not exist anywhere.
    let prevout = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x99; 32])), 0);
    let tx = make_tx(prevout, 9_000, script);
    let raw = hex_encode(&consensus_bytes(&tx));
    let handler = Handler::new(Arc::clone(&ctx));

    let err = handler
        .dispatch("sendrawtransaction", &json!([raw.as_str()]))
        .expect_err("missing-inputs tx should be rejected");
    assert_eq!(err.code(), RpcError::CORE_VERIFY_REJECTED);
}

#[test]
fn sendrawtransaction_idempotent_for_already_in_mempool() -> Result<(), Box<dyn std::error::Error>>
{
    let ctx = Arc::new(Context::new());
    let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
    let prevout = fund_utxo(&ctx, 0x43, 10_000);
    let tx = make_tx(prevout, 9_000, script);
    let txid = tx.txid();

    // Pre-insert into mempool.
    let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 1);
    ctx.mempool.pool().write().insert_entry(entry)?;

    let raw = hex_encode(&consensus_bytes(&tx));
    let handler = Handler::new(Arc::clone(&ctx));

    // Second submission should succeed without error.
    let result = handler.dispatch("sendrawtransaction", &json!([raw.as_str()]))?;
    assert_eq!(result.as_str(), Some(txid.to_string().as_str()));
    Ok(())
}

// ---------------------------------------------------------------------------
// testmempoolaccept — real evaluation
// ---------------------------------------------------------------------------

#[test]
fn testmempoolaccept_reports_allowed_for_valid_tx() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
    let prevout = fund_utxo(&ctx, 0x44, 10_000);
    let tx = make_tx(prevout, 9_000, script);
    let raw = hex_encode(&consensus_bytes(&tx));
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

    let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 1);
    ctx.mempool.pool().write().insert_entry(entry)?;

    let raw = hex_encode(&consensus_bytes(&tx));
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
    // The txid must still be reported correctly.
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
    let raw = hex_encode(&consensus_bytes(&tx));
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

// ---------------------------------------------------------------------------
// gettxout — mempool awareness
// ---------------------------------------------------------------------------

#[test]
fn gettxout_returns_unconfirmed_output_from_mempool() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = hex_decode(P2WPKH_SCRIPT_HEX)?;
    let tx = Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0xaa; 32])), 0),
            script_sig: Vec::new(),
            sequence: 0xFFFF_FFFE,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: 7_500,
            script_pubkey: script,
        }],
    };
    let txid = tx.txid();
    let entry = MempoolEntry::new(Arc::new(tx), 100, 500, 1, 1);
    ctx.mempool.pool().write().insert_entry(entry)?;

    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler.dispatch("gettxout", &json!([txid.to_string(), 0_u64]))?;

    // Should return the output with 0 confirmations (unconfirmed).
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
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0xbb; 32])), 0),
            script_sig: Vec::new(),
            sequence: 0xFFFF_FFFE,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: 7_500,
            script_pubkey: script,
        }],
    };
    let txid = tx.txid();
    let entry = MempoolEntry::new(Arc::new(tx), 100, 500, 1, 1);
    ctx.mempool.pool().write().insert_entry(entry)?;

    let handler = Handler::new(Arc::clone(&ctx));
    // include_mempool=false → skip mempool, output not in UTXO → null.
    let result = handler.dispatch("gettxout", &json!([txid.to_string(), 0_u64, false]))?;
    assert!(result.is_null(), "expected null when mempool is excluded");
    Ok(())
}

#[test]
fn gettxout_returns_null_for_outpoint_spent_in_mempool() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = hex_decode(P2WPKH_SCRIPT_HEX)?;

    // Fund a UTXO.
    let prevout = fund_utxo(&ctx, 0x55, 10_000);

    // Create a spending tx that spends the UTXO but is only in mempool.
    let spending_tx = make_tx(prevout, 9_000, script);
    let entry = MempoolEntry::new(Arc::new(spending_tx), 100, 1_000, 1, 1);
    ctx.mempool.pool().write().insert_entry(entry)?;

    // The original outpoint is now spent in mempool.
    let spent_txid = prevout.txid;
    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler.dispatch("gettxout", &json!([spent_txid.to_string(), 0_u64]))?;
    assert!(
        result.is_null(),
        "expected null for outpoint spent in mempool"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// createrawtransaction — requires parent to register the dispatch arm
// ---------------------------------------------------------------------------

#[test]
fn createrawtransaction_builds_valid_hex_tx() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));

    let inputs = json!([{
        "txid": "0000000000000000000000000000000000000000000000000000000000000001",
        "vout": 0
    }]);
    // Context::new() defaults to Mainnet, so use a valid mainnet address.
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
    // Use a regtest context so the address network matches.
    let mut ctx = Context::new();
    ctx.chain_network = bitcoin_rs_primitives::Network::Regtest;
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
    // replaceable=true → sequence < 0xFFFF_FFFE
    assert!(tx.inputs[0].sequence < 0xFFFF_FFFE);
    Ok(())
}

#[test]
fn createrawtransaction_rejects_duplicate_input() {
    let mut ctx = Context::new();
    ctx.chain_network = bitcoin_rs_primitives::Network::Regtest;
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
