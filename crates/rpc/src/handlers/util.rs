use alloc::sync::Arc;
use alloc::vec::Vec;
use core::str::FromStr as _;
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
        "isscript".to_owned(),
        serde_json::Value::Bool(script.is_p2sh() || script.is_p2wsh() || script.is_p2tr()),
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

pub(crate) fn getdescriptorinfo(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let descriptor = required_str(params, 0, "descriptor is required")?;
    // Strip any existing #XXXXXXXX checksum suffix.
    let payload = if let Some((body, _)) = descriptor.rsplit_once('#') {
        body
    } else {
        descriptor
    };
    let checksum = descriptor_checksum(payload).ok_or(RpcError::InvalidParams(
        "descriptor contains invalid characters",
    ))?;
    Ok(json!({
        "descriptor": format!("{payload}#{checksum}"),
        "checksum": checksum,
        "isrange": payload.contains('*'),
        "issolvable": false,
        "hasprivatekeys": false
    }))
}

pub(crate) fn deriveaddresses(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let descriptor = required_str(params, 0, "descriptor is required")?;
    let payload = required_checked_descriptor_payload(descriptor)?;
    // Match addr(...) wrapper.
    if let Some(inner) = strip_addr_wrapper(payload) {
        if inner.contains('*') {
            // TODO(miniscript): support ranged addr() once miniscript+derivation
            // is wired. For now return empty since we cannot enumerate.
            return Ok(json!([]));
        }
        let address = bitcoin::Address::from_str(inner)
            .map_err(|_| RpcError::InvalidParams("addr() contains an invalid address"))?;
        let address = address
            .require_network(bitcoin_network(ctx.chain_network))
            .map_err(|_| RpcError::InvalidParams("addr() address is for the wrong network"))?;
        return Ok(json!([address.to_string()]));
    }
    // TODO(miniscript): other wrappers (pkh, sh, wpkh, tr, wsh, multi, ...) need
    // miniscript-based key derivation. Return empty until then.
    Ok(json!([]))
}

fn required_checked_descriptor_payload(descriptor: &str) -> Result<&str, RpcError> {
    let Some((body, checksum)) = descriptor.rsplit_once('#') else {
        return Err(RpcError::InvalidParams("descriptor checksum is required"));
    };
    let expected = descriptor_checksum(body).ok_or(RpcError::InvalidParams(
        "descriptor contains invalid characters",
    ))?;
    if checksum == expected {
        Ok(body)
    } else {
        Err(RpcError::InvalidParams("descriptor checksum mismatch"))
    }
}

const fn bitcoin_network(network: bitcoin_rs_primitives::Network) -> bitcoin::Network {
    match network {
        bitcoin_rs_primitives::Network::Mainnet => bitcoin::Network::Bitcoin,
        bitcoin_rs_primitives::Network::Testnet3 => bitcoin::Network::Testnet,
        bitcoin_rs_primitives::Network::Testnet4 => bitcoin::Network::Testnet4,
        bitcoin_rs_primitives::Network::Signet => bitcoin::Network::Signet,
        bitcoin_rs_primitives::Network::Regtest => bitcoin::Network::Regtest,
    }
}

/// Returns the payload inside an `addr(...)` descriptor, if `payload` is one.
pub(crate) fn strip_addr_wrapper(payload: &str) -> Option<&str> {
    let stripped = payload.strip_prefix("addr(")?;
    let stripped = stripped.strip_suffix(')')?;
    Some(stripped)
}

const BIP380_INPUT_CHARSET: &str = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const BIP380_CHECKSUM_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BIP380_GENERATOR: [u64; 5] = [
    0x00f5_dee5_1989,
    0x00a9_fdca_3312,
    0x001b_ab10_e32d,
    0x0037_06b1_677a,
    0x0064_4d62_6ffd,
];

fn descriptor_polymod(c: u64, val: u32) -> u64 {
    let c0 = c >> 35;
    let mut result = ((c & 0x0007_ffff_ffff) << 5) ^ u64::from(val);
    let mut bit = 0;
    while bit < 5 {
        if (c0 >> bit) & 1 != 0 {
            result ^= BIP380_GENERATOR[bit];
        }
        bit += 1;
    }
    result
}

/// Computes the BIP380 descriptor checksum for `payload`.
pub(crate) fn descriptor_checksum(payload: &str) -> Option<String> {
    let mut c: u64 = 1;
    let mut cls: u64 = 0;
    let mut clscount: u64 = 0;
    for ch in payload.chars() {
        // INPUT_CHARSET is ASCII-only; find ch's byte position.
        let mut byte = [0_u8; 4];
        let encoded = ch.encode_utf8(&mut byte);
        if encoded.len() != 1 {
            return None;
        }
        let needle = encoded.as_bytes()[0];
        let pos = BIP380_INPUT_CHARSET
            .as_bytes()
            .iter()
            .position(|b| *b == needle)?;
        let pos_u64 = u64::try_from(pos).ok()?;
        let val = u32::try_from(pos_u64 & 31).ok()?;
        c = descriptor_polymod(c, val);
        cls = cls * 3 + (pos_u64 >> 5);
        clscount = clscount.saturating_add(1);
        if clscount == 3 {
            let val = u32::try_from(cls).ok()?;
            c = descriptor_polymod(c, val);
            cls = 0;
            clscount = 0;
        }
    }
    if clscount > 0 {
        let val = u32::try_from(cls).ok()?;
        c = descriptor_polymod(c, val);
    }
    for _ in 0..8_u32 {
        c = descriptor_polymod(c, 0);
    }
    c ^= 1;
    let mut out = String::with_capacity(8);
    for i in 0..8_u32 {
        let shift = 5_u32 * (7 - i);
        let idx = usize::try_from((c >> shift) & 31).ok()?;
        out.push(char::from(BIP380_CHECKSUM_CHARSET[idx]));
    }
    Some(out)
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

        let lifecycle = Arc::new(crate::RpcLifecycle::new(
            Arc::new(AtomicBool::new(false)),
            Instant::now(),
        ));
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

    #[test]
    fn validateaddress_reports_isscript_true_for_p2tr() {
        // Core's DescribeAddressVisitor returns isscript=true for
        // WitnessV1Taproot. The old predicate is_p2sh() || is_p2wsh() missed
        // P2TR entirely.
        let ctx = Arc::new(Context::new());
        // bc1p is a P2TR (Taproot) mainnet address.
        let result = validateaddress(
            &ctx,
            &json!(["bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"]),
        )
        .unwrap_or_else(|err| panic!("validateaddress failed: {err}"));
        let Some(isvalid) = result
            .get("isvalid")
            .and_then(sonic_rs::JsonValueTrait::as_bool)
        else {
            panic!("isvalid missing: {result:?}");
        };
        assert!(isvalid, "expected valid: {result:?}");
        let Some(isscript) = result
            .get("isscript")
            .and_then(sonic_rs::JsonValueTrait::as_bool)
        else {
            panic!("isscript missing: {result:?}");
        };
        assert!(isscript, "P2TR must report isscript=true: {result:?}");
    }

    #[test]
    fn validateaddress_reports_isscript_false_for_p2wpkh() {
        // Core's DescribeAddressVisitor returns isscript=false for
        // WitnessV0KeyHash (P2WPKH). The predicate must not match P2WPKH.
        let ctx = Arc::new(Context::new());
        // bc1q is a P2WPKH mainnet address.
        let result = validateaddress(&ctx, &json!(["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]))
            .unwrap_or_else(|err| panic!("validateaddress failed: {err}"));
        let Some(isvalid) = result
            .get("isvalid")
            .and_then(sonic_rs::JsonValueTrait::as_bool)
        else {
            panic!("isvalid missing: {result:?}");
        };
        assert!(isvalid, "expected valid: {result:?}");
        let Some(isscript) = result
            .get("isscript")
            .and_then(sonic_rs::JsonValueTrait::as_bool)
        else {
            panic!("isscript missing: {result:?}");
        };
        assert!(!isscript, "P2WPKH must report isscript=false: {result:?}");
    }
}

#[cfg(test)]
mod descriptor_checksum_tests {
    use alloc::sync::Arc;

    use super::*;

    #[test]
    fn getdescriptorinfo_emits_8_char_bech32_checksum() {
        let ctx = Arc::new(Context::new());
        let result = getdescriptorinfo(&ctx, &json!(["addr(1111111111111111111114oLvT2)"]))
            .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));
        let Some(checksum) = result.get("checksum").and_then(|v| v.as_str()) else {
            panic!("checksum missing: {result:?}");
        };
        assert_eq!(checksum.len(), 8, "checksum must be 8 chars: {checksum}");
        // All chars should be in the bech32 charset.
        for ch in checksum.chars() {
            assert!(
                BIP380_CHECKSUM_CHARSET.iter().any(|b| char::from(*b) == ch),
                "checksum char {ch} not in bech32 charset"
            );
        }
    }

    #[test]
    fn getdescriptorinfo_strips_existing_checksum() {
        let ctx = Arc::new(Context::new());
        let result = getdescriptorinfo(&ctx, &json!(["addr(x)#whatever"]))
            .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));
        let Some(desc) = result.get("descriptor").and_then(|v| v.as_str()) else {
            panic!("descriptor missing: {result:?}");
        };
        assert!(
            desc.starts_with("addr(x)#"),
            "expected addr(x)# prefix: {desc}"
        );
    }
}

#[cfg(test)]
mod deriveaddresses_tests {
    use alloc::sync::Arc;
    use sonic_rs::JsonContainerTrait as _;

    use super::*;

    #[test]
    fn deriveaddresses_returns_addr_argument_for_single_addr_descriptor() {
        let ctx = Arc::new(Context::new());
        let payload = "addr(1111111111111111111114oLvT2)";
        let checksum = descriptor_checksum(payload).unwrap_or_else(|| panic!("checksum failed"));
        let descriptor = format!("{payload}#{checksum}");
        let result = deriveaddresses(&ctx, &json!([descriptor]))
            .unwrap_or_else(|err| panic!("deriveaddresses failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert_eq!(arr.len(), 1);
        let Some(first) = arr.first().and_then(Value::as_str) else {
            panic!("expected string element: {result:?}");
        };
        assert_eq!(first, "1111111111111111111114oLvT2");
    }

    #[test]
    fn deriveaddresses_rejects_missing_checksum() {
        let ctx = Arc::new(Context::new());
        let result = deriveaddresses(&ctx, &json!(["addr(1111111111111111111114oLvT2)"]));
        assert!(
            matches!(result, Err(RpcError::InvalidParams(message)) if message.contains("checksum is required"))
        );
    }

    #[test]
    fn deriveaddresses_rejects_bad_checksum() {
        let ctx = Arc::new(Context::new());
        let result = deriveaddresses(&ctx, &json!(["addr(1111111111111111111114oLvT2)#aaaaaaaa"]));
        assert!(
            matches!(result, Err(RpcError::InvalidParams(message)) if message.contains("checksum mismatch"))
        );
    }

    #[test]
    fn deriveaddresses_rejects_fake_address_with_valid_descriptor_checksum() {
        let ctx = Arc::new(Context::new());
        let payload = "addr(not-an-address)";
        let checksum = descriptor_checksum(payload).unwrap_or_else(|| panic!("checksum failed"));
        let result = deriveaddresses(&ctx, &json!([format!("{payload}#{checksum}")]));
        assert!(
            matches!(result, Err(RpcError::InvalidParams(message)) if message.contains("invalid address"))
        );
    }

    #[test]
    fn deriveaddresses_empty_for_ranged_descriptors() {
        let ctx = Arc::new(Context::new());
        let payload = "wpkh(xpub.../0/*)";
        let checksum = descriptor_checksum(payload).unwrap_or_else(|| panic!("checksum failed"));
        let result = deriveaddresses(&ctx, &json!([format!("{payload}#{checksum}")]))
            .unwrap_or_else(|err| panic!("deriveaddresses failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert!(arr.is_empty());
    }
}
