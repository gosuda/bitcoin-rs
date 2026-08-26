use alloc::sync::Arc;
use alloc::vec::Vec;
use std::sync::OnceLock;
use std::time::Instant;

use bitcoin::Amount;
use sonic_rs::{JsonValueTrait, Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{params_array, required_str, required_u64, serde_to_sonic};
use crate::tx_render::btc_amount_json;

static SERVER_START: OnceLock<Instant> = OnceLock::new();

fn conf_target_blocks(conf_target: u64) -> u32 {
    u32::try_from(conf_target).unwrap_or(u32::MAX)
}

pub(crate) fn uptime(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    crate::handlers::ensure_no_params(params)?;
    let secs = if let Some(lifecycle) = ctx.rpc_lifecycle.as_ref() {
        lifecycle.uptime_secs()
    } else {
        // Isolated unit tests construct `Context::new` without a lifecycle.
        SERVER_START.get_or_init(Instant::now).elapsed().as_secs()
    };
    Ok(json!(secs))
}

pub(crate) fn getrpcinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    crate::handlers::ensure_no_params(params)?;
    let Some(lifecycle) = ctx.rpc_lifecycle.as_ref() else {
        return Err(RpcError::Internal(
            "rpc lifecycle is not configured".to_owned(),
        ));
    };
    let Some(path) = ctx.debug_log_path.as_ref() else {
        return Err(RpcError::Misc(
            "debug log path is not configured".to_owned(),
        ));
    };
    let active_commands: Vec<Value> = lifecycle
        .active_commands()
        .into_iter()
        .map(|(method, duration)| {
            json!({
                "method": method,
                "duration": duration
            })
        })
        .collect();
    Ok(json!({
        "active_commands": active_commands,
        "logpath": path.display().to_string()
    }))
}

pub(crate) fn getmemoryinfo(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let mode = array
        .first()
        .and_then(JsonValueTrait::as_str)
        .unwrap_or("stats");
    if mode != "stats" {
        // "mallocinfo" requires XML output; not implemented.
        return Err(RpcError::InvalidParams(
            "only mode=stats is supported in this implementation",
        ));
    }

    // Bitcoin Core reports locked-pool allocator stats. This implementation
    // exposes resident set size from Linux /proc as the available v1 proxy.
    let rss_bytes = read_linux_rss_bytes().unwrap_or(0);
    Ok(json!({
        "locked": {
            "used": rss_bytes,
            "free": 0_u64,
            "total": rss_bytes,
            "locked": 0_u64,
            "chunks_used": 0_u64,
            "chunks_free": 0_u64
        }
    }))
}

fn read_linux_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let trimmed = rest.trim().trim_end_matches(" kB");
            let kb: u64 = trimmed.parse().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

#[cfg(feature = "zmq")]
pub(crate) fn getzmqnotifications(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    crate::handlers::ensure_no_params(params)?;
    let notifications: Vec<_> = ctx
        .zmq_notifications()
        .iter()
        .map(|notification| {
            json!({
                "type": notification.notification_type.as_str(),
                "address": notification.address.as_str(),
                "hwm": notification.hwm
            })
        })
        .collect();
    Ok(json!(notifications))
}

pub(crate) fn estimatesmartfee(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let conf_target = required_u64(params, 0, "conf_target is required")?;
    let pool = ctx.mempool.read();
    match pool.estimate_fee_rate(conf_target_blocks(conf_target)) {
        Some(rate) => {
            let mut object = sonic_rs::Object::new();
            let _ = object.insert(
                "feerate",
                btc_amount_json(Amount::from_sat(rate.as_sat_per_kvb())),
            );
            let _ = object.insert("blocks", json!(conf_target));
            Ok(Value::from(object))
        }
        None => Ok(json!({
            "errors": ["Insufficient data or no feerate found"],
            "blocks": conf_target
        })),
    }
}

pub(crate) fn estimaterawfee(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let conf_target = required_u64(params, 0, "conf_target is required")?;
    let pool = ctx.mempool.read();
    let Some(rate) = pool.estimate_fee_rate(conf_target_blocks(conf_target)) else {
        return Ok(json!({}));
    };
    let feerate = btc_amount_json(Amount::from_sat(rate.as_sat_per_kvb()));
    let mut short = sonic_rs::Object::new();
    let _ = short.insert("feerate", feerate.clone());
    let mut medium = sonic_rs::Object::new();
    let _ = medium.insert("feerate", feerate.clone());
    let mut long = sonic_rs::Object::new();
    let _ = long.insert("feerate", feerate);
    let mut object = sonic_rs::Object::new();
    let _ = object.insert("short", Value::from(short));
    let _ = object.insert("medium", Value::from(medium));
    let _ = object.insert("long", Value::from(long));
    Ok(Value::from(object))
}

pub(crate) fn validateaddress(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    use core::str::FromStr as _;

    use bitcoin::hex::DisplayHex as _;

    let address_str = required_str(params, 0, "address is required")?;
    let network = crate::bitcoin_network(ctx.chain_network);
    let Ok(unchecked) = bitcoin::Address::from_str(address_str) else {
        return Ok(json!({ "isvalid": false }));
    };
    let Ok(address) = unchecked.require_network(network) else {
        return Ok(json!({ "isvalid": false }));
    };

    let script = address.script_pubkey();
    let script_hex = script.as_bytes().to_lower_hex_string();
    let address_canon = address.to_string();
    let mut response = serde_json::Map::new();
    response.insert("isvalid".to_owned(), serde_json::Value::Bool(true));
    response.insert(
        "address".to_owned(),
        serde_json::Value::String(address_canon),
    );
    response.insert(
        "scriptPubKey".to_owned(),
        serde_json::Value::String(script_hex),
    );
    response.insert(
        "isscript".to_owned(),
        serde_json::Value::Bool(script.is_p2sh() || script.is_p2wsh()),
    );
    response.insert(
        "iswitness".to_owned(),
        serde_json::Value::Bool(script.is_witness_program()),
    );
    if let Some(version) = script.witness_version() {
        response.insert(
            "witness_version".to_owned(),
            serde_json::Value::Number(i64::from(version.to_num()).into()),
        );
        // Witness program is the bytes after the 1-byte version prefix and 1-byte push opcode.
        let bytes = script.as_bytes();
        if bytes.len() >= 2 {
            response.insert(
                "witness_program".to_owned(),
                serde_json::Value::String(bytes[2..].to_lower_hex_string()),
            );
        }
    }

    serde_to_sonic(&serde_json::Value::Object(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::{JsonContainerTrait, JsonValueTrait};

    #[test]
    fn estimatesmartfee_reports_unavailable_when_estimator_has_no_history() {
        let ctx = Arc::new(Context::new());
        let result = estimatesmartfee(&ctx, &json!([3]))
            .unwrap_or_else(|err| panic!("estimatesmartfee failed: {err}"));
        assert!(
            result.get("feerate").is_none(),
            "unavailable estimator must omit feerate: {result:?}"
        );
        let Some(errors) = result.get("errors").and_then(JsonContainerTrait::as_array) else {
            panic!("errors missing: {result:?}");
        };
        assert_eq!(
            errors.first().and_then(JsonValueTrait::as_str),
            Some("Insufficient data or no feerate found")
        );
        assert_eq!(
            result.get("blocks").and_then(JsonValueTrait::as_u64),
            Some(3)
        );
    }

    #[test]
    fn estimaterawfee_returns_empty_object_when_estimator_unavailable() {
        let ctx = Arc::new(Context::new());
        let result = estimaterawfee(&ctx, &json!([2]))
            .unwrap_or_else(|err| panic!("estimaterawfee failed: {err}"));
        let Some(object) = result.as_object() else {
            panic!("expected object, got {result:?}");
        };
        assert!(
            object.is_empty(),
            "unavailable raw estimate must be empty: {result:?}"
        );
    }

    #[test]
    fn uptime_returns_u64_seconds() {
        let ctx = Arc::new(Context::new());
        let result = uptime(&ctx, &json!([])).unwrap_or_else(|err| panic!("uptime failed: {err}"));
        assert!(
            result.is_u64() || result.is_i64(),
            "uptime returns numeric: {result:?}"
        );
    }

    #[test]
    fn getrpcinfo_errors_without_lifecycle_or_log_path() {
        let ctx = Arc::new(Context::new());
        let err = match getrpcinfo(&ctx, &json!([])) {
            Err(err) => err,
            Ok(value) => panic!("getrpcinfo must require wiring: {value:?}"),
        };
        match err {
            RpcError::Internal(_) | RpcError::Misc(_) => {}
            other => panic!("expected Internal/Misc, got {other}"),
        }
    }

    #[test]
    fn getrpcinfo_returns_active_commands_and_logpath_when_wired() {
        use std::path::PathBuf;
        use std::sync::atomic::AtomicBool;

        let lifecycle = Arc::new(crate::RpcLifecycle::new(Arc::new(AtomicBool::new(false))));
        let ctx = Arc::new(
            Context::new()
                .with_rpc_lifecycle(Arc::clone(&lifecycle))
                .with_debug_log_path(PathBuf::from("/tmp/debug.log")),
        );
        let result =
            getrpcinfo(&ctx, &json!([])).unwrap_or_else(|err| panic!("getrpcinfo failed: {err}"));
        let Some(active) = result.get("active_commands").and_then(|v| v.as_array()) else {
            panic!("active_commands missing: {result:?}");
        };
        assert!(active.is_empty());
        let Some(logpath) = result.get("logpath").and_then(|v| v.as_str()) else {
            panic!("logpath missing: {result:?}");
        };
        assert_eq!(logpath, "/tmp/debug.log");
    }

    #[test]
    fn getmemoryinfo_returns_locked_stats_shape() {
        use alloc::sync::Arc;

        let ctx = Arc::new(Context::new());
        let result = getmemoryinfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getmemoryinfo failed: {err}"));
        assert!(result.get("locked").is_some(), "locked missing: {result:?}");
        let Some(locked) = result.get("locked") else {
            panic!("locked missing");
        };
        assert!(locked.get("used").is_some());
        assert!(locked.get("total").is_some());
    }

    #[test]
    fn getmemoryinfo_rejects_mallocinfo_mode() {
        use alloc::sync::Arc;

        let ctx = Arc::new(Context::new());
        let result = getmemoryinfo(&ctx, &json!(["mallocinfo"]));
        assert!(result.is_err());
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn getzmqnotifications_returns_empty_array() {
        use alloc::sync::Arc;

        let ctx = Arc::new(Context::new());
        let result = getzmqnotifications(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getzmqnotifications failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array, got {result:?}");
        };
        assert!(arr.is_empty());
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn getzmqnotifications_returns_active_metadata() {
        use alloc::sync::Arc;

        let ctx = Arc::new(Context::new().with_zmq_notifications(vec![
            crate::context::ZmqNotification::new("pubhashblock", "tcp://127.0.0.1:28332", 7),
        ]));
        let result = getzmqnotifications(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getzmqnotifications failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array, got {result:?}");
        };
        assert_eq!(arr.len(), 1);
        assert_eq!(
            arr[0].get("type").and_then(JsonValueTrait::as_str),
            Some("pubhashblock")
        );
        assert_eq!(
            arr[0].get("address").and_then(JsonValueTrait::as_str),
            Some("tcp://127.0.0.1:28332")
        );
        assert_eq!(arr[0].get("hwm").and_then(JsonValueTrait::as_u64), Some(7));
    }
}

#[cfg(test)]
mod validateaddress_tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::JsonValueTrait;

    #[test]
    fn validateaddress_returns_isvalid_false_for_garbage() {
        let ctx = Arc::new(Context::new());
        let result = validateaddress(&ctx, &json!(["not a real address"]))
            .unwrap_or_else(|err| panic!("validateaddress failed: {err}"));
        let Some(isvalid) = result
            .get("isvalid")
            .and_then(sonic_rs::JsonValueTrait::as_bool)
        else {
            panic!("isvalid missing: {result:?}");
        };
        assert!(!isvalid);
    }

    #[test]
    fn validateaddress_returns_isvalid_true_for_p2pkh_mainnet() {
        // ctx defaults to Mainnet network selector.
        let ctx = Arc::new(Context::new());
        // 1BoatSLRHtKNngkdXEeobR76b53LETtpyT is a famous P2PKH address.
        let result = validateaddress(&ctx, &json!(["1BoatSLRHtKNngkdXEeobR76b53LETtpyT"]))
            .unwrap_or_else(|err| panic!("validateaddress failed: {err}"));
        let Some(isvalid) = result
            .get("isvalid")
            .and_then(sonic_rs::JsonValueTrait::as_bool)
        else {
            panic!("isvalid missing: {result:?}");
        };
        assert!(isvalid, "expected valid: {result:?}");
    }
}
