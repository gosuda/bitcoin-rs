use alloc::sync::Arc;
use alloc::vec::Vec;
use std::sync::OnceLock;
use std::time::Instant;

use sonic_rs::{JsonValueTrait, Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{params_array, required_str, required_u64, serde_to_sonic};

static SERVER_START: OnceLock<Instant> = OnceLock::new();

const BLOCK_VSIZE_TARGET: u64 = 1_000_000;
const DEFAULT_MIN_FEERATE_SAT_PER_KVB: u64 = 1_000; // 1 sat/vB

fn estimate_feerate_sat_per_kvb(ctx: &Context, conf_target: u64) -> u64 {
    let mempool = ctx.mempool.read();
    if mempool.entries.is_empty() {
        return DEFAULT_MIN_FEERATE_SAT_PER_KVB;
    }

    let mut buckets: Vec<(u64, u64)> = Vec::new();
    for (_id, entry) in &mempool.entries {
        let Some((_, bucket_vsize)) = buckets
            .iter_mut()
            .find(|(bucket_rate, _)| *bucket_rate == entry.fee_rate)
        else {
            buckets.push((entry.fee_rate, u64::from(entry.vsize)));
            continue;
        };
        *bucket_vsize = bucket_vsize.saturating_add(u64::from(entry.vsize));
    }

    buckets.sort_unstable_by_key(|bucket| core::cmp::Reverse(bucket.0));

    let target_vsize = BLOCK_VSIZE_TARGET.saturating_mul(conf_target.max(1));
    let mut cumulative: u64 = 0;
    let mut threshold = DEFAULT_MIN_FEERATE_SAT_PER_KVB;
    for (rate, vsize) in &buckets {
        cumulative = cumulative.saturating_add(*vsize);
        threshold = *rate;
        if cumulative >= target_vsize {
            break;
        }
    }

    threshold.max(DEFAULT_MIN_FEERATE_SAT_PER_KVB)
}

fn sat_per_kvb_to_btc_per_kvb(sat: u64) -> f64 {
    f64::from(u32::try_from(sat).unwrap_or(u32::MAX)) / 100_000_000.0_f64
}

pub(crate) fn uptime(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    crate::handlers::ensure_no_params(params)?;
    let start = SERVER_START.get_or_init(Instant::now);
    let secs = start.elapsed().as_secs();
    Ok(json!(secs))
}

pub(crate) fn getrpcinfo(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    crate::handlers::ensure_no_params(params)?;
    // TODO(logpath): wire from Config.log_file once configured.
    Ok(json!({
        "active_commands": Vec::<String>::new(),
        "logpath": ""
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
    let rate_sat_per_kvb = estimate_feerate_sat_per_kvb(ctx, conf_target);
    let feerate = sat_per_kvb_to_btc_per_kvb(rate_sat_per_kvb);
    Ok(json!({
        "feerate": feerate,
        "blocks": conf_target
    }))
}

pub(crate) fn estimaterawfee(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let conf_target = required_u64(params, 0, "conf_target is required")?;
    let rate_sat_per_kvb = estimate_feerate_sat_per_kvb(ctx, conf_target);
    let feerate = sat_per_kvb_to_btc_per_kvb(rate_sat_per_kvb);
    Ok(json!({
        "short": {"feerate": feerate, "decay": 0.962, "scale": 1},
        "medium": {"feerate": feerate, "decay": 0.962, "scale": 1},
        "long": {"feerate": feerate, "decay": 0.962, "scale": 1}
    }))
}

pub(crate) fn validateaddress(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    use core::str::FromStr as _;

    use bitcoin::hex::DisplayHex as _;

    let address_str = required_str(params, 0, "address is required")?;
    let network = match ctx.chain_network {
        bitcoin_rs_primitives::Network::Mainnet => bitcoin::Network::Bitcoin,
        bitcoin_rs_primitives::Network::Testnet3 => bitcoin::Network::Testnet,
        bitcoin_rs_primitives::Network::Testnet4 => bitcoin::Network::Testnet4,
        bitcoin_rs_primitives::Network::Signet => bitcoin::Network::Signet,
        bitcoin_rs_primitives::Network::Regtest => bitcoin::Network::Regtest,
    };
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
    fn estimate_returns_default_when_mempool_empty() {
        let ctx = Arc::new(Context::new());
        let result = estimatesmartfee(&ctx, &json!([3]))
            .unwrap_or_else(|err| panic!("estimatesmartfee failed: {err}"));
        let Some(feerate) = result.get("feerate").and_then(JsonValueTrait::as_f64) else {
            panic!("feerate missing: {result:?}");
        };
        // Default min: 1000 sat/kvB / 100_000_000 = 0.00001
        assert!(
            feerate > 0.0,
            "empty mempool should still return a min feerate: {result:?}"
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
    fn getrpcinfo_returns_active_commands_array_and_logpath() {
        let ctx = Arc::new(Context::new());
        let result =
            getrpcinfo(&ctx, &json!([])).unwrap_or_else(|err| panic!("getrpcinfo failed: {err}"));
        let Some(active) = result.get("active_commands").and_then(|v| v.as_array()) else {
            panic!("active_commands missing: {result:?}");
        };
        assert!(active.is_empty());
        let Some(logpath) = result.get("logpath").and_then(|v| v.as_str()) else {
            panic!("logpath missing: {result:?}");
        };
        assert_eq!(logpath, "");
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
