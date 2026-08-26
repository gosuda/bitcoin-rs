//! Focused mempool and util RPC coverage through real Context/Mempool objects.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits};
use bitcoin_rs_rpc::context::Context;
use bitcoin_rs_rpc::{Handler, RpcError, RpcLifecycle};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, json};

fn bare_tx(label: u8) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            value: Amount::from_sat(50_000 + u64::from(label)),
            script_pubkey: ScriptBuf::from_bytes(vec![label]),
        }],
    }
}

fn amount_text(value: &sonic_rs::Value) -> String {
    if let Some(raw) = value.as_raw_number() {
        return raw.as_str().to_owned();
    }
    sonic_rs::to_string(value).unwrap_or_else(|err| panic!("amount encode failed: {err}"))
}

#[test]
fn getmempoolinfo_raises_min_fee_under_size_pressure() {
    let ctx = Arc::new(Context::new());
    {
        let mut pool = ctx.mempool.write();
        *pool = Mempool::new(MempoolLimits {
            max_total_bytes: 400,
            min_relay_fee_sat_per_kvb: 1_000,
            ..MempoolLimits::default()
        });
        // 200 vbytes is exactly half of 400 — pressure threshold.
        // fee_rate = 400 * 1000 / 200 = 2_000 sat/kvB
        pool.insert_entry(MempoolEntry::new(Arc::new(bare_tx(1)), 200, 400, 1, 1))
            .unwrap_or_else(|err| panic!("insert failed: {err}"));
    }

    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler
        .dispatch("getmempoolinfo", &json!([]))
        .unwrap_or_else(|err| panic!("getmempoolinfo failed: {err}"));
    let Some(mempool_min) = result.get("mempoolminfee") else {
        panic!("mempoolminfee missing: {result:?}");
    };
    // live_min_relay.max(2000 + 1000) = 3000 sat/kvB => 0.00003000 BTC/kvB
    assert_eq!(amount_text(mempool_min), "0.00003000");
}

#[test]
fn getmempoolentry_reflects_prioritise_fee_delta_in_modified_fee() {
    let ctx = Arc::new(Context::new());
    let tx = bare_tx(2);
    let txid = tx.compute_txid();
    {
        let mut pool = ctx.mempool.write();
        *pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7))
            .unwrap_or_else(|err| panic!("insert failed: {err}"));
        pool.prioritise(txid, 500)
            .unwrap_or_else(|err| panic!("prioritise failed: {err}"));
    }

    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler
        .dispatch("getmempoolentry", &json!([txid.to_string()]))
        .unwrap_or_else(|err| panic!("getmempoolentry failed: {err}"));
    let Some(base) = result.get("fees").and_then(|fees| fees.get("base")) else {
        panic!("fees.base missing: {result:?}");
    };
    let Some(modified) = result.get("fees").and_then(|fees| fees.get("modified")) else {
        panic!("fees.modified missing: {result:?}");
    };
    assert_eq!(amount_text(base), "0.00010000");
    assert_eq!(amount_text(modified), "0.00010500");
}

#[test]
fn estimatesmartfee_unavailable_then_available_after_block_removals() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));

    let unavailable = handler
        .dispatch("estimatesmartfee", &json!([2]))
        .unwrap_or_else(|err| panic!("estimatesmartfee failed: {err}"));
    assert!(
        unavailable.get("feerate").is_none(),
        "empty history must omit feerate: {unavailable:?}"
    );
    assert_eq!(
        unavailable
            .get("errors")
            .and_then(JsonContainerTrait::as_array)
            .and_then(|errors| errors.first())
            .and_then(JsonValueTrait::as_str),
        Some("Insufficient data or no feerate found")
    );

    let first = bare_tx(18);
    let first_txid = first.compute_txid();
    let second = bare_tx(19);
    let second_txid = second.compute_txid();
    {
        let mut pool = ctx.mempool.write();
        *pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        pool.insert_entry(MempoolEntry::new(
            Arc::new(first.clone()),
            100,
            10_000,
            1,
            7,
        ))
        .unwrap_or_else(|err| panic!("first insert failed: {err}"));
        pool.insert_entry(MempoolEntry::new(
            Arc::new(second.clone()),
            100,
            10_000,
            1,
            7,
        ))
        .unwrap_or_else(|err| panic!("second insert failed: {err}"));
        pool.remove_for_block(&[&first, &second], &[first_txid, second_txid], 8);
    }

    let available = handler
        .dispatch("estimatesmartfee", &json!([2]))
        .unwrap_or_else(|err| panic!("estimatesmartfee failed: {err}"));
    let Some(feerate) = available.get("feerate") else {
        panic!("feerate missing after confirmations: {available:?}");
    };
    let text = amount_text(feerate);
    assert!(
        text.contains('.')
            && text
                .split_once('.')
                .is_some_and(|(_, frac)| frac.len() == 8),
        "feerate must use exact eight decimals: {text}"
    );
    assert_eq!(
        available.get("blocks").and_then(JsonValueTrait::as_u64),
        Some(2)
    );

    let raw = handler
        .dispatch("estimaterawfee", &json!([2]))
        .unwrap_or_else(|err| panic!("estimaterawfee failed: {err}"));
    assert!(raw.get("short").and_then(|v| v.get("feerate")).is_some());
    assert!(raw.get("medium").and_then(|v| v.get("feerate")).is_some());
    assert!(raw.get("long").and_then(|v| v.get("feerate")).is_some());
}

#[test]
fn getrpcinfo_reports_empty_active_commands_and_logpath_when_wired() {
    let lifecycle = Arc::new(RpcLifecycle::new(
        Arc::new(AtomicBool::new(false)),
        Instant::now(),
    ));
    let ctx = Arc::new(
        Context::new()
            .with_rpc_lifecycle(Arc::clone(&lifecycle))
            .with_debug_log_path(PathBuf::from("/tmp/bitcoin-rs-debug.log")),
    );
    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler
        .dispatch("getrpcinfo", &json!([]))
        .unwrap_or_else(|err| panic!("getrpcinfo failed: {err}"));
    let Some(active) = result
        .get("active_commands")
        .and_then(JsonContainerTrait::as_array)
    else {
        panic!("active_commands missing: {result:?}");
    };
    assert!(active.is_empty());
    assert_eq!(
        result.get("logpath").and_then(JsonValueTrait::as_str),
        Some("/tmp/bitcoin-rs-debug.log")
    );
}

#[test]
fn fee_amount_fields_use_exact_eight_decimal_formatting() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler
        .dispatch("getmempoolinfo", &json!([]))
        .unwrap_or_else(|err| panic!("getmempoolinfo failed: {err}"));
    for key in [
        "total_fee",
        "mempoolminfee",
        "minrelaytxfee",
        "incrementalrelayfee",
    ] {
        let Some(amount) = result.get(key) else {
            panic!("{key} missing: {result:?}");
        };
        let text = amount_text(amount);
        let Some((_, frac)) = text.split_once('.') else {
            panic!("{key} missing decimal point: {text}");
        };
        assert_eq!(frac.len(), 8, "{key} must use eight decimals: {text}");
    }
}

#[test]
fn getrpcinfo_errors_when_lifecycle_facts_absent() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    let err = match handler.dispatch("getrpcinfo", &json!([])) {
        Err(err) => err,
        Ok(value) => panic!("getrpcinfo must require lifecycle wiring: {value:?}"),
    };
    match err {
        RpcError::Internal(_) | RpcError::Misc(_) => {}
        other => panic!("expected Internal/Misc, got {other}"),
    }
}
