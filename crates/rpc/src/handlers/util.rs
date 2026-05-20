use alloc::sync::Arc;
use alloc::vec::Vec;
use std::sync::OnceLock;
use std::time::Instant;

use sonic_rs::{Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{required_str, required_u64, serde_to_sonic};

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

    buckets.sort_unstable_by(|a, b| b.0.cmp(&a.0));

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

pub(crate) fn getzmqnotifications(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    crate::handlers::ensure_no_params(params)?;
    // bitcoin-rs does not yet support ZMQ pub/sub. Future strand may wire a real
    // notification publisher; meanwhile expose the canonical empty-array shape.
    Ok(json!(Vec::<sonic_rs::Value>::new()))
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
