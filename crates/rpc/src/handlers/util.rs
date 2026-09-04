use alloc::sync::Arc;
use alloc::vec::Vec;
use core::str::FromStr as _;
use std::sync::OnceLock;
use std::time::Instant;

use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json};

use corepc_types::v31;

use crate::compat::convert::{self, sat_to_btc, typed_to_sonic, typed_to_sonic_omitting_nulls};
use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{params_array, required_str, required_u64};

static SERVER_START: OnceLock<Instant> = OnceLock::new();

fn conf_target_blocks(conf_target: u64) -> u32 {
    u32::try_from(conf_target).unwrap_or(u32::MAX)
}

fn to_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn btc_amount_json(satoshis: u64) -> Value {
    let whole = satoshis / 100_000_000;
    let fractional = satoshis % 100_000_000;
    let text = format!("{whole}.{fractional:08}");
    let mut deserializer = sonic_rs::Deserializer::from_str(&text).use_rawnumber();
    match sonic_rs::Deserialize::deserialize(&mut deserializer) {
        Ok(value) => value,
        Err(error) => panic!("formatted unsigned BTC amount was invalid JSON: {error}"),
    }
}

pub(crate) fn uptime(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    crate::handlers::ensure_no_params(params)?;
    let start = SERVER_START.get_or_init(Instant::now);
    let secs = start.elapsed().as_secs();
    Ok(json!(secs))
}

pub(crate) fn getrpcinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    crate::handlers::ensure_no_params(params)?;
    let path = ctx
        .debug_log_path
        .as_ref()
        .ok_or_else(|| RpcError::Internal("debug log path is not configured".to_owned()))?;
    typed_to_sonic(&v31::GetRpcInfo {
        active_commands: Vec::new(),
        log_path: path.to_string_lossy().into_owned(),
    })
}

pub(crate) fn getmemoryinfo(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let mode = array
        .first()
        .and_then(JsonValueTrait::as_str)
        .unwrap_or("stats");
    if mode != "stats" {
        // Core's mallocinfo mode emits allocator XML; this node exposes stats only.
        return Err(RpcError::InvalidParams(
            "only mode=stats is supported in this implementation",
        ));
    }

    // Bitcoin Core reports locked-pool allocator stats. This implementation
    // exposes resident set size from Linux /proc as the available v1 proxy.
    let rss_bytes = read_linux_rss_bytes().unwrap_or(0);
    let mut locked = alloc::collections::BTreeMap::new();
    locked.insert(
        "locked".to_owned(),
        v31::Locked {
            used: rss_bytes,
            free: 0,
            total: rss_bytes,
            locked: 0,
            chunks_used: 0,
            chunks_free: 0,
        },
    );
    typed_to_sonic(&v31::GetMemoryInfoStats(locked))
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
    let notifications = ctx
        .zmq_notifications()
        .iter()
        .map(|notification| v31::GetZmqNotifications {
            type_: notification.notification_type.to_string(),
            address: notification.address.clone(),
            hwm: u64::from(notification.hwm),
        })
        .collect::<Vec<_>>();
    typed_to_sonic(&notifications)
}

pub(crate) fn estimatesmartfee(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let conf_target = required_u64(params, 0, "conf_target is required")?;
    let blocks = conf_target_blocks(conf_target);
    let pool = ctx.mempool.read();
    match pool.estimate_fee_rate(blocks) {
        Some(rate) => typed_to_sonic_omitting_nulls(&v31::EstimateSmartFee {
            fee_rate: Some(sat_to_btc(rate.as_sat_per_kvb())),
            errors: None,
            blocks,
        }),
        None => typed_to_sonic_omitting_nulls(&v31::EstimateSmartFee {
            fee_rate: None,
            errors: Some(alloc::vec![
                "Insufficient data or no feerate found".to_owned()
            ]),
            blocks,
        }),
    }
}

/// Local response shape: the fee estimator does not expose Core's
/// `decay`/`scale` internals, so `{short,medium,long}` carry `feerate` only
/// and the no-estimate branch stays `{}` (see the manifest row note).
pub(crate) fn estimaterawfee(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let conf_target = required_u64(params, 0, "conf_target is required")?;
    let pool = ctx.mempool.read();
    let Some(rate) = pool.estimate_fee_rate(conf_target_blocks(conf_target)) else {
        return Ok(json!({}));
    };
    let feerate = btc_amount_json(rate.as_sat_per_kvb());
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

/// Local response shape: an invalid address (malformed or wrong network)
/// answers Core's sparse `{"isvalid": false}` object only, which the pinned
/// corepc type cannot represent because its valid-address fields are
/// required; that branch is hand-built (see the manifest row note).
pub(crate) fn validateaddress(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    use core::str::FromStr as _;

    let address_str = required_str(params, 0, "address is required")?;
    let network = convert::bitcoin_network(ctx.chain_network);
    let Some(address) = bitcoin::Address::from_str(address_str)
        .ok()
        .and_then(|address| address.require_network(network).ok())
    else {
        // Core answers a malformed or wrong-network address with the sparse
        // `{"isvalid": false}` object alone: no address, scriptPubKey,
        // isscript, iswitness, or witness fields. `v31::ValidateAddress`
        // models the valid-address fields as required and cannot represent
        // that wire shape, so this branch is hand-built (local_shape
        // exception; see the manifest row note).
        return Ok(json!({"isvalid": false}));
    };

    let script = address.script_pubkey();
    let script_hex = to_lower_hex(script.as_bytes());
    let witness_version = script.witness_version();
    let witness_program = witness_version
        .filter(|_| script.as_bytes().len() >= 2)
        .map(|_| to_lower_hex(&script.as_bytes()[2..]));
    typed_to_sonic(&v31::ValidateAddress {
        is_valid: true,
        address: address.to_string(),
        script_pubkey: script_hex,
        is_script: script.is_p2sh() || script.is_p2wsh(),
        is_witness: script.is_witness_program(),
        witness_version: witness_version.map(|version| i64::from(version.to_num())),
        witness_program,
    })
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
    typed_to_sonic(&v31::GetDescriptorInfo {
        descriptor: format!("{payload}#{checksum}"),
        multipath_expansion: None,
        checksum,
        is_range: payload.contains('*'),
        is_solvable: false,
        has_private_keys: false,
    })
}

pub(crate) fn deriveaddresses(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let descriptor = required_str(params, 0, "descriptor is required")?;
    let payload = required_checked_descriptor_payload(descriptor)?;
    // Match addr(...) wrapper.
    if let Some(inner) = strip_addr_wrapper(payload) {
        if params.as_array().is_some_and(|args| args.len() > 1) {
            return Err(RpcError::MethodDisabled(
                "range arguments are unavailable without a wallet",
            ));
        }
        if inner.contains('*') {
            return Err(RpcError::MethodDisabled(
                "ranged descriptors are unavailable without a wallet",
            ));
        }
        let address = bitcoin::Address::from_str(inner)
            .map_err(|_| RpcError::InvalidParams("addr() contains an invalid address"))?;
        let address = address
            .require_network(convert::bitcoin_network(ctx.chain_network))
            .map_err(|_| RpcError::InvalidParams("addr() address is for the wrong network"))?;
        return typed_to_sonic(&v31::DeriveAddresses(alloc::vec![address.to_string()]));
    }
    Err(RpcError::MethodDisabled(
        "only addr() descriptors are available without a wallet",
    ))
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
    fn getrpcinfo_requires_a_configured_log_path() {
        let ctx = Arc::new(Context::new());
        let result = getrpcinfo(&ctx, &json!([]));
        assert!(
            matches!(result, Err(RpcError::Internal(message)) if message == "debug log path is not configured")
        );
    }

    #[test]
    fn getrpcinfo_returns_active_commands_and_configured_log_path() {
        let ctx = Arc::new(
            Context::new().with_debug_log_path(std::path::PathBuf::from("/tmp/debug.log")),
        );
        let result =
            getrpcinfo(&ctx, &json!([])).unwrap_or_else(|err| panic!("getrpcinfo failed: {err}"));
        assert!(
            result
                .get("active_commands")
                .and_then(Value::as_array)
                .is_some_and(sonic_rs::Array::is_empty)
        );
        assert_eq!(
            result.get("logpath").and_then(|value| value.as_str()),
            Some("/tmp/debug.log")
        );
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

    /// Both invalid classes must answer exactly `{"isvalid": false}`: the
    /// valid-only fields are absent, never default-valued.
    fn assert_sparse_invalid(result: &Value) {
        let object = result
            .as_object()
            .unwrap_or_else(|| panic!("not an object: {result:?}"));
        assert_eq!(object.len(), 1, "expected exactly one key: {result:?}");
        let Some(isvalid) = result
            .get("isvalid")
            .and_then(sonic_rs::JsonValueTrait::as_bool)
        else {
            panic!("isvalid missing: {result:?}");
        };
        assert!(!isvalid);
        for field in [
            "address",
            "scriptPubKey",
            "isscript",
            "iswitness",
            "witness_version",
            "witness_program",
        ] {
            assert!(
                result.get(field).is_none(),
                "{field} must be absent: {result:?}"
            );
        }
    }

    #[test]
    fn validateaddress_returns_sparse_object_for_garbage() {
        let ctx = Arc::new(Context::new());
        let result = validateaddress(&ctx, &json!(["not a real address"]))
            .unwrap_or_else(|err| panic!("validateaddress failed: {err}"));
        assert_sparse_invalid(&result);
    }

    #[test]
    fn validateaddress_returns_sparse_object_for_wrong_network() {
        // ctx defaults to the Mainnet selector; this testnet address parses
        // but fails require_network, and Core answers it sparsely too.
        let ctx = Arc::new(Context::new());
        let result = validateaddress(&ctx, &json!(["tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"]))
            .unwrap_or_else(|err| panic!("validateaddress failed: {err}"));
        assert_sparse_invalid(&result);
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
    fn deriveaddresses_rejects_wallet_only_descriptors() {
        let ctx = Arc::new(Context::new());
        let payload = "wpkh(xpub.../0/*)";
        let checksum = descriptor_checksum(payload).unwrap_or_else(|| panic!("checksum failed"));
        let result = deriveaddresses(&ctx, &json!([format!("{payload}#{checksum}")]));
        assert!(matches!(result, Err(RpcError::MethodDisabled(_))));
    }
}
