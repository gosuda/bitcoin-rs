use alloc::sync::Arc;
use alloc::vec::Vec;
use core::str::FromStr as _;

use miniscript::DefiniteDescriptorKey;
use miniscript::Descriptor as MiniscriptDescriptor;
use miniscript::ForEachKey as _;
use miniscript::descriptor::{DescriptorPublicKey, DescriptorSecretKey, KeyMap};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json};

use bitcoin_rs_primitives::Network;
use corepc_types::v31;

use bitcoin::hex::DisplayHex as _;

use crate::context::Context;
use crate::convert::{self, sat_to_btc, typed_to_sonic, typed_to_sonic_omitting_nulls};
use crate::error::RpcError;
use crate::handlers::{
    ensure_at_most_params, params_array, required_i64, required_str, required_u64,
};

/// Core `MAX_CONFIRM_TARGET` in `policy/fees.h`.
const ESTIMATE_SMART_FEE_MAX_TARGET_I64: i64 = 1008;
const ESTIMATE_SMART_FEE_TARGET_ERROR: &str = "Invalid conf_target, must be between 1 and 1008";
const ESTIMATE_SMART_FEE_MODE_ERROR: &str =
    "Invalid estimate_mode parameter, must be UNSET, ECONOMICAL or CONSERVATIVE";

fn conf_target_blocks(conf_target: u64) -> u32 {
    u32::try_from(conf_target).unwrap_or(u32::MAX)
}

pub(crate) fn decodescript(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let bound = super::bind_named_params(params, &["hexstring"])?;
    let params = bound.as_ref();
    let array = params_array(params)?;
    if array.len() != 1 {
        return Err(RpcError::Misc("decodescript \"hexstring\"".to_owned()));
    }
    let hex = array[0]
        .as_str()
        .ok_or_else(|| super::wrong_type(1, "hexstring", &array[0], "string"))?;
    if hex.len() > crate::server::MAX_BODY_BYTES {
        return Err(RpcError::InvalidParameter(
            "script exceeds the RPC request byte limit".to_owned(),
        ));
    }
    let script = bitcoin::ScriptBuf::from_hex(hex).map_err(|_| {
        RpcError::InvalidParameter(format!("argument must be hexadecimal string (not '{hex}')"))
    })?;
    Ok(crate::tx_render::decoded_script_json(
        script.as_bytes(),
        ctx.chain.chain_network,
    ))
}

pub(crate) fn uptime(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    crate::handlers::ensure_no_params(params)?;
    let secs = ctx.server_start().elapsed().as_secs();
    Ok(json!(secs))
}

pub(crate) fn getrpcinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    crate::handlers::ensure_no_params(params)?;
    let path = ctx
        .debug_log_path
        .as_ref()
        .ok_or_else(|| RpcError::Internal("debug log path is not configured".to_owned()))?;
    typed_to_sonic(&v31::GetRpcInfo {
        active_commands: ctx
            .active_calls
            .snapshot()
            .into_iter()
            .map(|(method, duration)| v31::ActiveCommand { method, duration })
            .collect(),
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
        return Err(RpcError::InvalidParams(
            "only mode=stats is supported in this implementation",
        ));
    }

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
        .into_iter()
        .map(|notification| v31::GetZmqNotifications {
            type_: notification.topic.notifier_type().to_string(),
            address: notification.endpoint,
            hwm: u64::from(notification.hwm),
        })
        .collect::<Vec<_>>();
    typed_to_sonic(&notifications)
}

pub(crate) fn estimatesmartfee(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_at_most_params(params, 2)?;
    let conf_target = required_i64(params, 0, "conf_target is required")?;
    if !(1_i64..=ESTIMATE_SMART_FEE_MAX_TARGET_I64).contains(&conf_target) {
        return Err(RpcError::InvalidParameter(
            ESTIMATE_SMART_FEE_TARGET_ERROR.to_owned(),
        ));
    }
    parse_estimate_mode(params)?;
    let conf_target = u64::try_from(conf_target)
        .map_err(|_| RpcError::InvalidParameter(ESTIMATE_SMART_FEE_TARGET_ERROR.to_owned()))?;
    let blocks = conf_target_blocks(conf_target);
    let pool = ctx.mempool.gateway.read();
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

fn parse_estimate_mode(params: &Value) -> Result<(), RpcError> {
    let Some(array) = params.as_array() else {
        return Ok(());
    };
    let Some(value) = array.get(1) else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let Some(mode) = value.as_str() else {
        return Err(RpcError::InvalidType(
            "parameter must be a string".to_owned(),
        ));
    };
    if is_core_fee_estimate_mode(mode) {
        return Ok(());
    }
    Err(RpcError::InvalidParameter(
        ESTIMATE_SMART_FEE_MODE_ERROR.to_owned(),
    ))
}

fn is_core_fee_estimate_mode(mode: &str) -> bool {
    mode.eq_ignore_ascii_case("unset")
        || mode.eq_ignore_ascii_case("economical")
        || mode.eq_ignore_ascii_case("conservative")
}

/// Local response shape: the fee estimator does not expose Core's
/// `decay`/`scale` internals, so `{short,medium,long}` carry `feerate` only
/// and the no-estimate branch stays `{}` (see the manifest row note).
pub(crate) fn estimaterawfee(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let conf_target = required_u64(params, 0, "conf_target is required")?;
    let pool = ctx.mempool.gateway.read();
    let Some(rate) = pool.estimate_fee_rate(conf_target_blocks(conf_target)) else {
        return Ok(json!({}));
    };
    let feerate = crate::tx_render::btc_amount_json(rate.as_sat_per_kvb());
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
    let network = convert::bitcoin_network(ctx.chain.chain_network);
    let Some(address) = bitcoin::Address::from_str(address_str)
        .ok()
        .and_then(|address| address.require_network(network).ok())
    else {
        return Ok(json!({"isvalid": false}));
    };

    let script = address.script_pubkey();
    let script_hex = script.as_bytes().to_lower_hex_string();
    let witness_version = script.witness_version();
    let witness_program = witness_version
        .filter(|_| script.as_bytes().len() >= 2)
        .map(|_| script.as_bytes()[2..].to_lower_hex_string());
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

pub(crate) fn getdescriptorinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let descriptor = required_str(params, 0, "descriptor is required")?;
    let (payload, checksum) = checked_checksum(descriptor, ChecksumRequirement::Optional)?;

    let info = analyse(payload, convert::bitcoin_network(ctx.chain.chain_network))
        .map_err(descriptor_error)?;

    typed_to_sonic_omitting_nulls(&v31::GetDescriptorInfo {
        descriptor: with_checksum(&info.canonical),
        multipath_expansion: if info.multipath_expansion.is_empty() {
            None
        } else {
            Some(
                info.multipath_expansion
                    .iter()
                    .map(|expansion| with_checksum(expansion))
                    .collect(),
            )
        },
        checksum,
        is_range: info.is_range,
        is_solvable: info.is_solvable,
        has_private_keys: info.has_private_keys,
    })
}

pub(crate) fn deriveaddresses(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let descriptor = required_str(params, 0, "descriptor is required")?;
    let (payload, _checksum) = checked_checksum(descriptor, ChecksumRequirement::Required)?;
    let range = array
        .get(1)
        .filter(|value| !value.is_null())
        .map(parse_derivation_range)
        .transpose()?;

    let expansions = derive_descriptor_addresses(
        payload,
        convert::bitcoin_network(ctx.chain.chain_network),
        range,
    )
    .map_err(descriptor_error)?;

    match <[Vec<String>; 1]>::try_from(expansions) {
        Ok([single]) => typed_to_sonic(&v31::DeriveAddresses(single)),
        Err(many) => typed_to_sonic(&v31::DeriveAddressesMultipath(
            many.into_iter().map(v31::DeriveAddresses).collect(),
        )),
    }
}

/// A descriptor that does not parse is `-5`; a range that does not match a
/// descriptor that parsed fine is `-8`. They are different questions and Core
fn descriptor_error(error: DescriptorError) -> RpcError {
    match error {
        DescriptorError::Range(message) => RpcError::InvalidParameter(message.to_owned()),
        DescriptorError::PrivateKeys => {
            RpcError::InvalidAddressOrKey(GENERATEBLOCK_NEEDS_PRIVATE_KEYS.to_owned())
        }
        DescriptorError::Parse(message) => RpcError::InvalidAddressOrKey(message),
    }
}

fn with_checksum(canonical: &str) -> String {
    descriptor_checksum(canonical)
        .map_or_else(|| canonical.to_owned(), |sum| format!("{canonical}#{sum}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChecksumRequirement {
    Optional,
    Required,
}

fn checked_checksum(
    descriptor: &str,
    requirement: ChecksumRequirement,
) -> Result<(&str, String), RpcError> {
    checksummed_payload(descriptor, requirement).map_err(RpcError::InvalidAddressOrKey)
}

fn checksummed_payload(
    descriptor: &str,
    requirement: ChecksumRequirement,
) -> Result<(&str, String), String> {
    let mut parts = descriptor.split('#');
    let Some(payload) = parts.next() else {
        return Err("Invalid characters in payload".to_owned());
    };
    let supplied = parts.next();
    if parts.next().is_some() {
        return Err("Multiple '#' symbols".to_owned());
    }
    if supplied.is_none() && requirement == ChecksumRequirement::Required {
        return Err("Missing checksum".to_owned());
    }
    if let Some(supplied) = supplied
        && supplied.len() != 8
    {
        return Err(format!(
            "Expected 8 character checksum, not {} characters",
            supplied.len()
        ));
    }

    let computed =
        descriptor_checksum(payload).ok_or_else(|| "Invalid characters in payload".to_owned())?;
    if let Some(supplied) = supplied
        && supplied != computed
    {
        return Err(format!(
            "Provided checksum '{supplied}' does not match computed checksum '{computed}'"
        ));
    }
    Ok((payload, computed))
}

/// Bitcoin Core's `ParseDescriptorRange`: an end, or an inclusive `[begin,end]`.
pub(crate) fn parse_derivation_range(value: &Value) -> Result<(u32, u32), RpcError> {
    let integer = |value: &Value| {
        value
            .as_i64()
            .ok_or_else(|| RpcError::Misc("JSON integer out of range".into()))
    };
    let (begin, end) = if value.is_number() {
        (0, integer(value)?)
    } else if let Some(pair) = value
        .as_array()
        .filter(|pair| pair.len() == 2 && pair.iter().all(JsonValueTrait::is_number))
    {
        let begin = integer(&pair[0])?;
        let end = integer(&pair[1])?;
        if begin > end {
            return Err(RpcError::InvalidParameter(
                "Range specified as [begin,end] must not have begin after end".into(),
            ));
        }
        (begin, end)
    } else {
        return Err(RpcError::InvalidParameter(
            "Range must be specified as end or as [begin,end]".into(),
        ));
    };
    if begin < 0 {
        return Err(RpcError::InvalidParameter(
            "Range should be greater or equal than 0".into(),
        ));
    }
    if !(0..=i64::from(MAX_DERIVATION_INDEX)).contains(&end) {
        return Err(RpcError::InvalidParameter(
            "End of range is too high".into(),
        ));
    }
    let begin = u32::try_from(begin)
        .map_err(|_| RpcError::InvalidParameter("End of range is too high".into()))?;
    let end = u32::try_from(end)
        .map_err(|_| RpcError::InvalidParameter("End of range is too high".into()))?;
    bound_derivation_work(begin, end)?;
    Ok((begin, end))
}

const MAX_DERIVATION_COUNT: u32 = 1_000_000;

const MAX_DERIVATION_INDEX: u32 = (1 << 31) - 1;

fn bound_derivation_work(begin: u32, end: u32) -> Result<(), RpcError> {
    if u64::from(end) >= u64::from(begin).saturating_add(u64::from(MAX_DERIVATION_COUNT)) {
        return Err(RpcError::InvalidParameter("Range is too large".to_owned()));
    }
    Ok(())
}

pub(crate) struct ScanScript {
    pub(crate) script_pubkey: Vec<u8>,
    pub(crate) desc: String,
}

pub(crate) enum ScanDescriptor {
    Fixed(ScanScript),
    Keys {
        descriptor: Box<MiniscriptDescriptor<DescriptorPublicKey>>,
        kind: &'static str,
        range: (u32, u32),
    },
}

impl ScanDescriptor {
    pub(crate) fn script_count(&self) -> usize {
        match self {
            Self::Fixed(_) => 1,
            Self::Keys {
                descriptor,
                range: (begin, end),
                ..
            } => {
                let mut paths = 1;
                descriptor.for_each_key(|key| {
                    if let DescriptorPublicKey::MultiXPub(key) = key {
                        paths = key.derivation_paths.paths().len();
                    }
                    true
                });
                paths.saturating_mul(usize::try_from(end - begin + 1).unwrap_or(usize::MAX))
            }
        }
    }

    pub(crate) fn expand(
        self,
        cancelled: &impl Fn() -> Result<bool, RpcError>,
        mut insert: impl FnMut(ScanScript) -> Result<(), RpcError>,
    ) -> Result<(), RpcError> {
        if cancelled()? {
            return Ok(());
        }
        let (descriptor, kind, (begin, end)) = match self {
            Self::Fixed(script) => return insert(script),
            Self::Keys {
                descriptor,
                kind,
                range,
            } => (descriptor, kind, range),
        };
        let paths = descriptor
            .into_single_descriptors()
            .map_err(|error| RpcError::InvalidAddressOrKey(error.to_string()))?;
        for index in begin..=end {
            for path in &paths {
                if cancelled()? {
                    return Ok(());
                }
                let derived = path
                    .at_derivation_index(index)
                    .map_err(|error| RpcError::InvalidAddressOrKey(error.to_string()))?;
                insert(scan_key_script(&derived, kind)?)?;
            }
        }
        Ok(())
    }
}

pub(crate) fn scan_descriptor(
    text: &str,
    range: Option<(u32, u32)>,
    network: Network,
) -> Result<ScanDescriptor, RpcError> {
    let (payload, _) = checked_checksum(text, ChecksumRequirement::Optional)?;
    let chain = convert::bitcoin_network(network);
    if let Some(raw) = parse_unspendable(payload) {
        let script = match raw.map_err(descriptor_error)? {
            Unspendable::Address(address) => address
                .require_network(chain)
                .map_err(|_| RpcError::InvalidAddressOrKey("Address is not valid".into()))?
                .script_pubkey(),
            Unspendable::Raw(script) => script,
        };
        return Ok(ScanDescriptor::Fixed(ScanScript {
            desc: crate::tx_render::script_descriptor(script.as_bytes(), network),
            script_pubkey: script.into_bytes(),
        }));
    }
    let descriptor = MiniscriptDescriptor::<DescriptorPublicKey>::from_str(payload)
        .map_err(|error| RpcError::InvalidAddressOrKey(error.to_string()))?;
    ensure_keys_match_network(&descriptor, chain).map_err(descriptor_error)?;
    if descriptor_needs_private_keys(&descriptor) {
        return Err(RpcError::InvalidAddressOrKey(
            GENERATEBLOCK_NEEDS_PRIVATE_KEYS.into(),
        ));
    }
    let kind =
        match &descriptor {
            MiniscriptDescriptor::Pkh(_) => "pkh",
            MiniscriptDescriptor::Wpkh(_) => "wpkh",
            MiniscriptDescriptor::Sh(sh)
                if matches!(sh.as_inner(), miniscript::descriptor::ShInner::Wpkh(_)) =>
            {
                "sh(wpkh"
            }
            MiniscriptDescriptor::Tr(tr) if tr.tap_tree().is_none() => "tr",
            _ => return Err(RpcError::InvalidParameter(
                "Supported scan descriptors are addr, raw, pkh, wpkh, sh(wpkh), and key-only tr"
                    .into(),
            )),
        };
    if let Some(DescriptorPublicKey::MultiXPub(key)) = descriptor.iter_pk().next() {
        let mut seen = std::collections::BTreeSet::new();
        if key
            .derivation_paths
            .paths()
            .iter()
            .any(|path| !seen.insert(path))
        {
            return Err(RpcError::InvalidAddressOrKey(
                "Duplicate multipath derivation paths are not supported".into(),
            ));
        }
    }
    let range = if descriptor.has_wildcard() {
        range.unwrap_or((0, 1000))
    } else {
        (0, 0)
    };
    Ok(ScanDescriptor::Keys {
        descriptor: Box::new(descriptor),
        kind,
        range,
    })
}

fn scan_key_script(
    derived: &MiniscriptDescriptor<DefiniteDescriptorKey>,
    kind: &str,
) -> Result<ScanScript, RpcError> {
    let key = derived
        .iter_pk()
        .next()
        .ok_or_else(|| RpcError::Internal("descriptor has no public key".into()))?;
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let public = key.derive_public_key(&secp);
    let path = key
        .full_derivation_path()
        .ok_or_else(|| RpcError::Internal("fixed descriptor has no derivation path".into()))?;
    let path = path.to_string().replace('\'', "h");
    let suffix = if path.is_empty() {
        String::new()
    } else {
        format!("/{path}")
    };
    let fingerprint = match key.as_descriptor_public_key() {
        DescriptorPublicKey::Single(single) if single.origin.is_none() => public
            .pubkey_hash()
            .to_string()
            .chars()
            .take(8)
            .collect::<String>(),
        _ => key.master_fingerprint().to_string(),
    };
    let origin = format!("[{fingerprint}{suffix}]");
    let public = if kind == "tr" {
        public.inner.x_only_public_key().0.to_string()
    } else {
        public.to_string()
    };
    let suffix = if kind == "sh(wpkh" { "))" } else { ")" };
    Ok(ScanScript {
        script_pubkey: derived.script_pubkey().into_bytes(),
        desc: with_checksum(&format!("{kind}({origin}{public}{suffix}")),
    })
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "descriptor scanner interface retained for callers and tests"
    )
)]
pub(crate) fn scan_descriptor_range(
    text: &str,
    network: Network,
    range: Option<(u32, u32)>,
    cancelled: impl Fn() -> Result<bool, RpcError>,
) -> Result<Vec<ScanScript>, RpcError> {
    scan_descriptor_range_budgeted(text, network, range, 1024_u64, 1_048_576_u64, cancelled)
}

#[expect(
    clippy::too_many_lines,
    reason = "descriptor range expansion and budget validation"
)]
pub(crate) fn scan_descriptor_range_budgeted(
    text: &str,
    network: Network,
    range: Option<(u32, u32)>,
    remaining_scripts: u64,
    remaining_bytes: u64,
    cancelled: impl Fn() -> Result<bool, RpcError>,
) -> Result<Vec<ScanScript>, RpcError> {
    let (payload, _) = checked_checksum(text, ChecksumRequirement::Optional)?;
    let chain = convert::bitcoin_network(network);
    if let Some(raw) = parse_unspendable(payload) {
        if remaining_scripts < 1 {
            return Err(RpcError::InvalidParameter(
                "At most 1024 scan descriptors are supported".into(),
            ));
        }
        let script = match raw.map_err(descriptor_error)? {
            Unspendable::Address(address) => address
                .require_network(chain)
                .map_err(|_| RpcError::InvalidAddressOrKey("Address is not valid".into()))?
                .script_pubkey(),
            Unspendable::Raw(script) => script,
        };
        let script_len = u64::try_from(script.len())
            .map_err(|_| RpcError::InvalidParameter("Scan script byte limit exceeded".into()))?;
        if script_len > remaining_bytes {
            return Err(RpcError::InvalidParameter(
                "Scan script byte limit exceeded".into(),
            ));
        }
        return Ok(vec![ScanScript {
            desc: crate::tx_render::script_descriptor(script.as_bytes(), network),
            script_pubkey: script.into_bytes(),
        }]);
    }
    let descriptor = MiniscriptDescriptor::<DescriptorPublicKey>::from_str(payload)
        .map_err(|error| RpcError::InvalidAddressOrKey(error.to_string()))?;
    ensure_keys_match_network(&descriptor, chain).map_err(descriptor_error)?;
    if descriptor_needs_private_keys(&descriptor) {
        return Err(RpcError::InvalidAddressOrKey(
            GENERATEBLOCK_NEEDS_PRIVATE_KEYS.into(),
        ));
    }
    let kind = match &descriptor {
        MiniscriptDescriptor::Pkh(_) => "pkh",
        MiniscriptDescriptor::Wpkh(_) => "wpkh",
        MiniscriptDescriptor::Sh(sh)
            if matches!(sh.as_inner(), miniscript::descriptor::ShInner::Wpkh(_)) =>
        {
            "sh(wpkh"
        }
        MiniscriptDescriptor::Tr(tr) if tr.tap_tree().is_none() => "tr",
        _ => {
            return Err(RpcError::InvalidParameter(
                "Supported scan descriptors are addr, raw, pkh, wpkh, sh(wpkh), and key-only tr"
                    .into(),
            ));
        }
    };
    let is_range = descriptor.has_wildcard();
    let (begin, end) = if is_range {
        range.unwrap_or((0, 1000))
    } else {
        (0, 0)
    };
    let paths = if descriptor.is_multipath() {
        #[expect(
            clippy::redundant_clone,
            reason = "explicit clone before into_single_descriptors"
        )]
        descriptor
            .clone()
            .into_single_descriptors()
            .map_err(|error| RpcError::InvalidAddressOrKey(error.to_string()))?
    } else {
        vec![descriptor]
    };
    let paths_len = u64::try_from(paths.len()).map_err(|_| {
        RpcError::InvalidParameter("At most 1024 scan descriptors are supported".into())
    })?;
    let count = paths_len.saturating_mul(
        u64::from(end)
            .saturating_sub(u64::from(begin))
            .saturating_add(1),
    );
    if count > remaining_scripts {
        return Err(RpcError::InvalidParameter(
            "At most 1024 scan descriptors are supported".into(),
        ));
    }
    let max_script_size: u64 = match kind {
        "pkh" => 25,
        "wpkh" => 22,
        "sh(wpkh" => 23,
        _ => 34,
    };
    let preflight_bytes = count.saturating_mul(max_script_size);
    if preflight_bytes > remaining_bytes {
        return Err(RpcError::InvalidParameter(
            "Scan script byte limit exceeded".into(),
        ));
    }
    let count_usize = usize::try_from(count).map_err(|_| {
        RpcError::InvalidParameter("At most 1024 scan descriptors are supported".into())
    })?;
    let mut scripts = Vec::with_capacity(count_usize);
    'outer: for index in begin..=end {
        for path in &paths {
            if cancelled()? {
                break 'outer;
            }
            let derived = path
                .at_derivation_index(index)
                .map_err(|error| RpcError::InvalidAddressOrKey(error.to_string()))?;
            let script = scan_key_script(&derived, kind)?;
            scripts.push(script);
        }
    }
    Ok(scripts)
}

#[derive(Debug)]
struct DescriptorInfo {
    /// Canonical form, with private keys replaced by their public counterparts.
    canonical: String,
    /// One entry per multipath expansion; empty for a single-path descriptor.
    multipath_expansion: Vec<String>,
    /// Whether the descriptor carries a `*`, and so describes a range.
    is_range: bool,
    /// Whether the descriptor carries enough information to produce a spend.
    is_solvable: bool,
    /// Whether the *input* carried at least one private key.
    has_private_keys: bool,
}

enum DescriptorError {
    Parse(String),
    Range(&'static str),
    PrivateKeys,
}

impl core::fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parse(message) => write!(f, "{message}"),
            Self::Range(message) => write!(f, "{message}"),
            Self::PrivateKeys => write!(f, "{GENERATEBLOCK_NEEDS_PRIVATE_KEYS}"),
        }
    }
}

fn analyse(text: &str, network: bitcoin::Network) -> Result<DescriptorInfo, DescriptorError> {
    if let Some(key) = parse_combo(text)? {
        let combo = parse_combo_info(key, network)?;
        return Ok(DescriptorInfo {
            canonical: combo.canonical,
            multipath_expansion: combo.multipath_expansion,
            is_range: combo.is_range,
            is_solvable: true,
            has_private_keys: combo.has_private_keys,
        });
    }
    let secp = bitcoin::secp256k1::Secp256k1::signing_only();
    match MiniscriptDescriptor::<DescriptorPublicKey>::parse_descriptor(&secp, text) {
        Ok((descriptor, keys)) => {
            ensure_keys_match_network(&descriptor, network)?;
            let has_private_keys = !keys.is_empty();
            ensure_secret_keys_match_network(keys, network)?;
            let multipath_expansion = if descriptor.is_multipath() {
                descriptor
                    .clone()
                    .into_single_descriptors()
                    .map_err(|error| DescriptorError::Parse(error.to_string()))?
                    .iter()
                    .map(ToString::to_string)
                    .collect()
            } else {
                Vec::new()
            };
            let canonical = multipath_expansion
                .first()
                .cloned()
                .unwrap_or_else(|| descriptor.to_string());
            Ok(DescriptorInfo {
                canonical,
                multipath_expansion,
                is_range: descriptor.has_wildcard(),
                is_solvable: true,
                has_private_keys,
            })
        }
        Err(error) => match parse_unspendable(text) {
            Some(unspendable) => {
                let unspendable = unspendable?;
                if let Unspendable::Address(address) = &unspendable {
                    address
                        .clone()
                        .require_network(network)
                        .map_err(|error| DescriptorError::Parse(error.to_string()))?;
                }
                Ok(DescriptorInfo {
                    canonical: unspendable.canonical(),
                    multipath_expansion: Vec::new(),
                    is_range: false,
                    is_solvable: false,
                    has_private_keys: false,
                })
            }
            None => Err(DescriptorError::Parse(error.to_string())),
        },
    }
}

fn parse_combo(text: &str) -> Result<Option<&str>, DescriptorError> {
    if let Some(key) = text
        .strip_prefix("combo(")
        .and_then(|s| s.strip_suffix(')'))
    {
        if key.is_empty() {
            return Err(DescriptorError::Parse("Invalid combo descriptor".into()));
        }
        return Ok(Some(key));
    }
    Ok(None)
}

struct ComboInfo {
    canonical: String,
    multipath_expansion: Vec<String>,
    is_range: bool,
    has_private_keys: bool,
    paths: Vec<MiniscriptDescriptor<DescriptorPublicKey>>,
}

fn parse_combo_info(key: &str, network: bitcoin::Network) -> Result<ComboInfo, DescriptorError> {
    let secp = bitcoin::secp256k1::Secp256k1::signing_only();
    let (descriptor, parsed_keys) = MiniscriptDescriptor::<DescriptorPublicKey>::parse_descriptor(
        &secp,
        &format!("pkh({key})"),
    )
    .map_err(|error| DescriptorError::Parse(error.to_string()))?;
    ensure_keys_match_network(&descriptor, network)?;
    let has_private_keys = !parsed_keys.is_empty();
    ensure_secret_keys_match_network(parsed_keys, network)?;

    let is_range = descriptor.has_wildcard();
    let is_multipath = descriptor.is_multipath();
    let paths = if is_multipath {
        descriptor
            .into_single_descriptors()
            .map_err(|error| DescriptorError::Parse(error.to_string()))?
    } else {
        vec![descriptor]
    };
    let forms = paths
        .iter()
        .map(combo_from_pkh)
        .collect::<Result<Vec<_>, _>>()?;
    let canonical = forms
        .first()
        .cloned()
        .ok_or_else(|| DescriptorError::Parse("Invalid combo descriptor".into()))?;
    Ok(ComboInfo {
        canonical,
        multipath_expansion: if is_multipath { forms } else { Vec::new() },
        is_range,
        has_private_keys,
        paths,
    })
}

fn combo_from_pkh(
    descriptor: &MiniscriptDescriptor<DescriptorPublicKey>,
) -> Result<String, DescriptorError> {
    let form = descriptor.to_string();
    let body = form
        .split_once('#')
        .map_or(form.as_str(), |(prefix, _)| prefix);
    let key = body
        .strip_prefix("pkh(")
        .and_then(|rest| rest.strip_suffix(')'))
        .ok_or_else(|| DescriptorError::Parse("Invalid combo key".into()))?;
    Ok(format!("combo({key})"))
}

fn require_range_match(
    is_range: bool,
    range: Option<(u32, u32)>,
) -> Result<(u32, u32), DescriptorError> {
    match (is_range, range) {
        (true, None) => Err(DescriptorError::Range(
            "Range must be specified for a ranged descriptor",
        )),
        (false, Some(_)) => Err(DescriptorError::Range(
            "Range should not be specified for an un-ranged descriptor",
        )),
        (false, None) => Ok((0, 0)),
        (true, Some(bounds)) => Ok(bounds),
    }
}

fn derive_descriptor_addresses(
    text: &str,
    network: bitcoin::Network,
    range: Option<(u32, u32)>,
) -> Result<Vec<Vec<String>>, DescriptorError> {
    if let Some(key) = parse_combo(text)? {
        let combo = parse_combo_info(key, network)?;
        let (begin, end) = require_range_match(combo.is_range, range)?;
        let mut expansions = Vec::with_capacity(combo.paths.len());
        for path in combo.paths {
            expansions.push(derive_combo_addresses(&path, network, begin, end)?);
        }
        return Ok(expansions);
    }

    if let Some(unspendable) = parse_unspendable(text) {
        if range.is_some() {
            return Err(DescriptorError::Range(
                "Range should not be specified for an un-ranged descriptor",
            ));
        }
        return Ok(vec![vec![unspendable?.address(network)?]]);
    }

    let secp = bitcoin::secp256k1::Secp256k1::signing_only();
    let (descriptor, keys) =
        MiniscriptDescriptor::<DescriptorPublicKey>::parse_descriptor(&secp, text)
            .map_err(|error| DescriptorError::Parse(error.to_string()))?;

    let (begin, end) = require_range_match(descriptor.has_wildcard(), range)?;
    ensure_keys_match_network(&descriptor, network)?;
    ensure_secret_keys_match_network(keys, network)?;

    let paths = if descriptor.is_multipath() {
        descriptor
            .into_single_descriptors()
            .map_err(|error| DescriptorError::Parse(error.to_string()))?
    } else {
        vec![descriptor]
    };

    let mut expansions = Vec::with_capacity(paths.len());
    for path in paths {
        let mut addresses = Vec::new();
        for index in begin..=end {
            let derived = path
                .at_derivation_index(index)
                .map_err(|error| DescriptorError::Parse(error.to_string()))?;
            let address = derived.address(network).map_err(|_error| {
                DescriptorError::Parse(
                    "Descriptor does not have a corresponding address".to_owned(),
                )
            })?;
            addresses.push(address.to_string());
        }
        expansions.push(addresses);
    }
    Ok(expansions)
}

fn derive_combo_addresses(
    path: &MiniscriptDescriptor<DescriptorPublicKey>,
    network: bitcoin::Network,
    begin: u32,
    end: u32,
) -> Result<Vec<String>, DescriptorError> {
    let mut addresses = Vec::new();
    for index in begin..=end {
        let derived = path
            .at_derivation_index(index)
            .map_err(|error| DescriptorError::Parse(error.to_string()))?;
        addresses.push(descriptor_address(&derived, network)?);
        let key = combo_key(&derived)?;
        if let Ok(wpkh) = MiniscriptDescriptor::new_wpkh(key.clone()) {
            addresses.push(descriptor_address(&wpkh, network)?);
            let sh_wpkh = MiniscriptDescriptor::new_sh_wpkh(key)
                .map_err(|error| DescriptorError::Parse(error.to_string()))?;
            addresses.push(descriptor_address(&sh_wpkh, network)?);
        }
    }
    Ok(addresses)
}

fn combo_key(
    descriptor: &MiniscriptDescriptor<DefiniteDescriptorKey>,
) -> Result<DefiniteDescriptorKey, DescriptorError> {
    descriptor
        .iter_pk()
        .next()
        .ok_or_else(|| DescriptorError::Parse("Invalid combo key".into()))
}

fn descriptor_address(
    descriptor: &MiniscriptDescriptor<DefiniteDescriptorKey>,
    network: bitcoin::Network,
) -> Result<String, DescriptorError> {
    descriptor
        .address(network)
        .map(|address| address.to_string())
        .map_err(|_error| {
            DescriptorError::Parse("Descriptor does not have a corresponding address".to_owned())
        })
}

fn ensure_keys_match_network(
    descriptor: &MiniscriptDescriptor<DescriptorPublicKey>,
    network: bitcoin::Network,
) -> Result<(), DescriptorError> {
    let wanted = bitcoin::NetworkKind::from(network);
    let mut offender = None;
    let _all_matched = descriptor.for_each_key(|key| {
        let found = match key {
            DescriptorPublicKey::XPub(xkey) => Some(xkey.xkey.network),
            DescriptorPublicKey::MultiXPub(xkey) => Some(xkey.xkey.network),
            DescriptorPublicKey::Single(_) => None,
        };
        if let Some(found) = found
            && found != wanted
        {
            offender = Some(found);
            return false;
        }
        true
    });

    match offender {
        None => Ok(()),
        Some(found) => Err(network_mismatch(found, network)),
    }
}

fn ensure_secret_keys_match_network(
    secrets: KeyMap,
    network: bitcoin::Network,
) -> Result<(), DescriptorError> {
    let wanted = bitcoin::NetworkKind::from(network);
    for (_public, secret) in secrets {
        let found = match secret {
            DescriptorSecretKey::Single(single) => single.key.network,
            DescriptorSecretKey::XPrv(xkey) => xkey.xkey.network,
            DescriptorSecretKey::MultiXPrv(xkey) => xkey.xkey.network,
        };
        if found != wanted {
            return Err(network_mismatch(found, network));
        }
    }
    Ok(())
}

fn network_mismatch(found: bitcoin::NetworkKind, network: bitcoin::Network) -> DescriptorError {
    DescriptorError::Parse(format!(
        "Descriptor key is for {} but this node is on {network}",
        if found == bitcoin::NetworkKind::Main {
            "mainnet"
        } else {
            "a test network"
        }
    ))
}

enum Unspendable {
    Address(bitcoin::Address<bitcoin::address::NetworkUnchecked>),
    Raw(bitcoin::ScriptBuf),
}

impl Unspendable {
    fn canonical(&self) -> String {
        match self {
            Self::Address(address) => format!("addr({})", address.clone().assume_checked()),
            Self::Raw(script) => format!("raw({})", script.to_hex_string()),
        }
    }

    fn address(&self, network: bitcoin::Network) -> Result<String, DescriptorError> {
        match self {
            Self::Address(address) => address
                .clone()
                .require_network(network)
                .map(|address| address.to_string())
                .map_err(|error| DescriptorError::Parse(error.to_string())),
            Self::Raw(script) => bitcoin::Address::from_script(script, network)
                .map(|address| address.to_string())
                .map_err(|_error| {
                    DescriptorError::Parse(
                        "Descriptor does not have a corresponding address".to_owned(),
                    )
                }),
        }
    }
}

fn parse_unspendable(text: &str) -> Option<Result<Unspendable, DescriptorError>> {
    let body = text.strip_suffix(')')?;
    if let Some(address) = body.strip_prefix("addr(") {
        return Some(
            bitcoin::Address::from_str(address)
                .map(Unspendable::Address)
                .map_err(|error| DescriptorError::Parse(error.to_string())),
        );
    }
    let hex = body.strip_prefix("raw(")?;
    Some(
        bitcoin::ScriptBuf::from_hex(hex)
            .map(Unspendable::Raw)
            .map_err(|error| DescriptorError::Parse(error.to_string())),
    )
}

pub(crate) const GENERATEBLOCK_INVALID_OUTPUT: &str = "Error: Invalid address or descriptor";
pub(crate) const GENERATEBLOCK_MULTIPATH: &str = "Multipath descriptor not accepted";
pub(crate) const GENERATEBLOCK_RANGED: &str =
    "Ranged descriptor not accepted. Maybe pass through deriveaddresses first?";
pub(crate) const GENERATEBLOCK_NEEDS_PRIVATE_KEYS: &str =
    "Cannot derive script without private keys";

/// Coinbase script for `generateblock`'s `output` argument (`API-05`).
/// CONTRACT: docs/contracts/external-api.md#API-29
/// CONTRACT: docs/contracts/external-api.md#API-31
pub(crate) fn generateblock_payout_script(
    text: &str,
    network: bitcoin::Network,
) -> Result<Vec<u8>, RpcError> {
    match script_from_descriptor(text, network) {
        Ok(script) => Ok(script),
        Err(error @ (DescriptorError::Range(_) | DescriptorError::PrivateKeys)) => {
            Err(descriptor_error(error))
        }
        Err(_) => payout_script_from_address(text, network, GENERATEBLOCK_INVALID_OUTPUT),
    }
}

pub(crate) fn payout_script_from_address(
    text: &str,
    network: bitcoin::Network,
    invalid_message: &'static str,
) -> Result<Vec<u8>, RpcError> {
    let unchecked = bitcoin::Address::from_str(text)
        .map_err(|_| RpcError::InvalidAddressOrKey(invalid_message.to_owned()))?;
    let address = unchecked
        .require_network(network)
        .map_err(|_| RpcError::InvalidAddressOrKey(invalid_message.to_owned()))?;
    Ok(address.script_pubkey().as_bytes().to_vec())
}

fn script_from_descriptor(
    text: &str,
    network: bitcoin::Network,
) -> Result<Vec<u8>, DescriptorError> {
    let (payload, _) =
        checksummed_payload(text, ChecksumRequirement::Optional).map_err(DescriptorError::Parse)?;
    if let Some(key) = parse_combo(payload)? {
        return combo_payout_script(key, network);
    }

    if let Some(unspendable) = parse_unspendable(payload) {
        return match unspendable? {
            Unspendable::Address(address) => {
                let address = address
                    .require_network(network)
                    .map_err(|error| DescriptorError::Parse(error.to_string()))?;
                Ok(address.script_pubkey().as_bytes().to_vec())
            }
            Unspendable::Raw(script) => Ok(script.as_bytes().to_vec()),
        };
    }

    let checksummed = descriptor_text_with_optional_checksum(payload)?;
    let secp = bitcoin::secp256k1::Secp256k1::signing_only();
    let (descriptor, keys) =
        MiniscriptDescriptor::<DescriptorPublicKey>::parse_descriptor(&secp, &checksummed)
            .map_err(|error| DescriptorError::Parse(error.to_string()))?;
    ensure_keys_match_network(&descriptor, network)?;
    ensure_secret_keys_match_network(keys, network)?;
    if descriptor.is_multipath() {
        return Err(multipath_descriptor_rejected());
    }
    if descriptor.has_wildcard() {
        return Err(ranged_descriptor_rejected());
    }
    if descriptor_needs_private_keys(&descriptor) {
        return Err(DescriptorError::PrivateKeys);
    }
    let derived = descriptor
        .at_derivation_index(0)
        .map_err(|_| DescriptorError::PrivateKeys)?;
    Ok(derived.script_pubkey().as_bytes().to_vec())
}

fn combo_payout_script(key: &str, network: bitcoin::Network) -> Result<Vec<u8>, DescriptorError> {
    let combo = parse_combo_info(key, network)?;
    if combo.paths.len() != 1 {
        return Err(multipath_descriptor_rejected());
    }
    if combo.is_range {
        return Err(ranged_descriptor_rejected());
    }
    let path = combo
        .paths
        .first()
        .ok_or_else(|| DescriptorError::Parse("Invalid combo descriptor".into()))?;
    if descriptor_needs_private_keys(path) {
        return Err(DescriptorError::PrivateKeys);
    }
    let derived = path
        .at_derivation_index(0)
        .map_err(|_| DescriptorError::PrivateKeys)?;
    let pk = MiniscriptDescriptor::new_pk(combo_key(&derived)?);
    Ok(pk.script_pubkey().as_bytes().to_vec())
}

fn multipath_descriptor_rejected() -> DescriptorError {
    DescriptorError::Range(GENERATEBLOCK_MULTIPATH)
}

fn descriptor_needs_private_keys(descriptor: &MiniscriptDescriptor<DescriptorPublicKey>) -> bool {
    let mut needs = false;
    descriptor.for_each_key(|key| {
        needs |= match key {
            DescriptorPublicKey::XPub(xkey) => {
                derivation_path_has_hardened_step(&xkey.derivation_path)
            }
            DescriptorPublicKey::MultiXPub(xkey) => xkey
                .derivation_paths
                .paths()
                .iter()
                .any(derivation_path_has_hardened_step),
            DescriptorPublicKey::Single(_) => false,
        };
        true
    });
    needs
}

fn derivation_path_has_hardened_step(path: &bitcoin::bip32::DerivationPath) -> bool {
    path.as_ref()
        .iter()
        .any(bitcoin::bip32::ChildNumber::is_hardened)
}

fn ranged_descriptor_rejected() -> DescriptorError {
    DescriptorError::Range(GENERATEBLOCK_RANGED)
}

fn descriptor_text_with_optional_checksum(text: &str) -> Result<String, DescriptorError> {
    if text.contains('#') {
        return Ok(text.to_owned());
    }
    let checksum = descriptor_checksum(text)
        .ok_or_else(|| DescriptorError::Parse("Invalid descriptor".into()))?;
    Ok(format!("{text}#{checksum}"))
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

pub(crate) fn descriptor_checksum(payload: &str) -> Option<String> {
    let mut c: u64 = 1;
    let mut cls: u64 = 0;
    let mut clscount: u64 = 0;
    for ch in payload.chars() {
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
    fn estimatesmartfee_rejects_conf_target_outside_core_range() {
        let ctx = Arc::new(Context::new());
        for target in [-1_i64, 0, 1009] {
            let error = match estimatesmartfee(&ctx, &json!([target])) {
                Err(e) => e,
                Ok(_) => panic!("conf_target {target} outside 1..=1008 must fail"),
            };
            assert!(matches!(error, RpcError::InvalidParameter(_)));
            assert_eq!(error.code(), RpcError::CORE_INVALID_PARAMETER);
            assert_eq!(error.to_string(), ESTIMATE_SMART_FEE_TARGET_ERROR);
        }
    }

    #[test]
    fn estimatesmartfee_rejects_unknown_estimate_mode() {
        let ctx = Arc::new(Context::new());
        let unknown_mode = match estimatesmartfee(&ctx, &json!([3, "hurry"])) {
            Err(e) => e,
            Ok(_) => panic!("unknown estimate_mode must fail"),
        };
        assert!(matches!(unknown_mode, RpcError::InvalidParameter(_)));
        assert_eq!(unknown_mode.code(), RpcError::CORE_INVALID_PARAMETER);
        assert_eq!(unknown_mode.to_string(), ESTIMATE_SMART_FEE_MODE_ERROR);

        let typed_mode = match estimatesmartfee(&ctx, &json!([3, 1])) {
            Err(e) => e,
            Ok(_) => panic!("non-string estimate_mode must fail"),
        };
        assert!(matches!(typed_mode, RpcError::InvalidType(_)));
        assert_eq!(typed_mode.code(), RpcError::CORE_INVALID_TYPE);
    }

    #[test]
    fn estimatesmartfee_accepts_core_estimate_modes_and_rejects_trailing() {
        let ctx = Arc::new(Context::new());
        for params in [
            json!([3, "unset"]),
            json!([3, "ECONOMICAL"]),
            json!([3, "Conservative"]),
            json!([3, null]),
            json!([3]),
        ] {
            estimatesmartfee(&ctx, &params)
                .unwrap_or_else(|err| panic!("{params:?} must be accepted: {err}"));
        }

        let extra = match estimatesmartfee(&ctx, &json!([3, "conservative", 1])) {
            Err(e) => e,
            Ok(_) => panic!("trailing estimatesmartfee arguments must fail"),
        };
        assert!(matches!(extra, RpcError::InvalidParams(_)));
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
    fn getrpcinfo_needs_a_configured_log_path_and_reports_it() {
        let bare = Arc::new(Context::new());
        assert!(
            matches!(getrpcinfo(&bare, &json!([])), Err(RpcError::Internal(message)) if message == "debug log path is not configured")
        );

        let mut ctx = Context::new();
        ctx.debug_log_path = Some(std::path::PathBuf::from("/tmp/debug.log"));
        let ctx = Arc::new(ctx);
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
    fn getrpcinfo_reports_held_calls_oldest_first_and_removes_by_identity() {
        let mut ctx = Context::new();
        ctx.debug_log_path = Some(std::path::PathBuf::from("/tmp/debug.log"));
        let ctx = Arc::new(ctx);

        let first = ctx.active_calls.begin("getblock");
        let second = ctx.active_calls.begin("getblock");
        let result =
            getrpcinfo(&ctx, &json!([])).unwrap_or_else(|err| panic!("getrpcinfo failed: {err}"));
        let commands = result
            .get("active_commands")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("active_commands missing: {result:?}"));
        assert_eq!(commands.len(), 2, "both held calls are active: {result:?}");
        for command in commands {
            assert_eq!(
                command.get("method").and_then(Value::as_str),
                Some("getblock")
            );
            assert!(
                command
                    .get("duration")
                    .and_then(JsonValueTrait::as_u64)
                    .is_some(),
                "duration is elapsed microseconds: {command:?}"
            );
        }

        drop(first);
        let result =
            getrpcinfo(&ctx, &json!([])).unwrap_or_else(|err| panic!("getrpcinfo failed: {err}"));
        let commands = result
            .get("active_commands")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("active_commands missing: {result:?}"));
        assert_eq!(
            commands.len(),
            1,
            "dropping one guard removes exactly its own entry: {result:?}"
        );
        drop(second);
        let snapshot = ctx.active_calls.snapshot();
        assert!(snapshot.is_empty(), "all held calls removed: {snapshot:?}");
    }

    #[test]
    fn dispatch_registers_the_call_and_unknown_methods_never_register() {
        let mut ctx = Context::new();
        ctx.debug_log_path = Some(std::path::PathBuf::from("/tmp/debug.log"));
        let handler = crate::handlers::Handler::new(Arc::new(ctx));

        let result = handler
            .dispatch("getrpcinfo", &json!([]))
            .unwrap_or_else(|err| panic!("getrpcinfo dispatch failed: {err}"));
        let commands = result
            .get("active_commands")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("active_commands missing: {result:?}"));
        assert_eq!(commands.len(), 1, "getrpcinfo includes itself: {result:?}");
        assert_eq!(
            commands[0].get("method").and_then(Value::as_str),
            Some("getrpcinfo")
        );
        assert!(
            handler.context().active_calls.snapshot().is_empty(),
            "no residue after the call returns"
        );

        assert!(handler.dispatch("nosuchmethod", &json!([])).is_err());
        assert!(
            handler.context().active_calls.snapshot().is_empty(),
            "unknown methods never register"
        );
    }

    #[test]
    fn getmemoryinfo_reports_resident_bytes_as_the_whole_locked_pool() {
        use alloc::sync::Arc;

        let ctx = Arc::new(Context::new());
        let result = getmemoryinfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getmemoryinfo failed: {err}"));
        let Some(locked) = result.get("locked") else {
            panic!("locked missing: {result:?}");
        };
        let field = |name: &str| {
            locked
                .get(name)
                .and_then(JsonValueTrait::as_u64)
                .unwrap_or_else(|| panic!("{name} is not an unsigned number: {locked:?}"))
        };
        let used = field("used");
        if read_linux_rss_bytes().is_some() {
            assert!(used > 0, "resident set size read as zero: {locked:?}");
        }
        assert_eq!(used, field("total"), "the proxy pool is fully used");
        for name in ["free", "locked", "chunks_used", "chunks_free"] {
            assert_eq!(
                field(name),
                0,
                "{name} has no meaning for the resident-set proxy"
            );
        }
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
    fn getzmqnotifications_returns_active_metadata() {
        use alloc::sync::Arc;

        #[derive(Debug)]
        struct NotifierPublisher;
        impl crate::zmq::ZmqPublisher for NotifierPublisher {
            fn active_notifiers(&self) -> Vec<crate::zmq::ZmqNotifier> {
                vec![crate::zmq::ZmqNotifier {
                    topic: crate::zmq::ZmqTopic::HashBlock,
                    endpoint: "tcp://127.0.0.1:28332".to_string(),
                    hwm: 7,
                }]
            }
            fn publish_hashblock(&self, _hash: bitcoin_rs_primitives::Hash256) {}
            fn publish_hashtx(&self, _txid: bitcoin_rs_primitives::Txid) {}
            fn publish_rawblock(&self, _bytes: &[u8]) {}
            fn publish_rawtx(&self, _bytes: &[u8]) {}
        }
        let bare = Arc::new(Context::new());
        let empty = getzmqnotifications(&bare, &json!([]))
            .unwrap_or_else(|err| panic!("getzmqnotifications failed: {err}"));
        assert_eq!(
            empty.as_array().map(sonic_rs::Array::len),
            Some(0),
            "{empty:?}"
        );

        let mut ctx = Context::new();
        ctx.zmq_publisher = Arc::new(NotifierPublisher);
        let ctx = Arc::new(ctx);
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
        let ctx = Arc::new(Context::new());
        let result = validateaddress(&ctx, &json!(["tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"]))
            .unwrap_or_else(|err| panic!("validateaddress failed: {err}"));
        assert_sparse_invalid(&result);
    }

    #[test]
    fn validateaddress_returns_isvalid_true_for_p2pkh_mainnet() {
        let ctx = Arc::new(Context::new());
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

    const ADDRESS: &str = "1111111111111111111114oLvT2";

    #[test]
    fn getdescriptorinfo_emits_8_char_bech32_checksum() {
        let ctx = Arc::new(Context::new());
        let result = getdescriptorinfo(&ctx, &json!(["addr(1111111111111111111114oLvT2)"]))
            .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));
        let Some(checksum) = result.get("checksum").and_then(|v| v.as_str()) else {
            panic!("checksum missing: {result:?}");
        };
        assert_eq!(checksum.len(), 8, "checksum must be 8 chars: {checksum}");
        for ch in checksum.chars() {
            assert!(
                BIP380_CHECKSUM_CHARSET.iter().any(|b| char::from(*b) == ch),
                "checksum char {ch} not in bech32 charset"
            );
        }
    }

    #[test]
    fn the_checksum_matches_the_bip380_vector() {
        const DESCRIPTOR: &str = "raw(deadbeef)";
        const CHECKSUM: &str = "89f8spxm";

        let ctx = Arc::new(Context::new());
        let result = getdescriptorinfo(&ctx, &json!([DESCRIPTOR]))
            .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));
        assert_eq!(
            result.get("checksum").and_then(JsonValueTrait::as_str),
            Some(CHECKSUM)
        );

        let with_checksum = getdescriptorinfo(&ctx, &json!([format!("{DESCRIPTOR}#{CHECKSUM}")]))
            .unwrap_or_else(|err| panic!("a correct checksum must be accepted: {err}"));
        assert_eq!(
            with_checksum
                .get("checksum")
                .and_then(JsonValueTrait::as_str),
            Some(CHECKSUM)
        );
    }

    #[test]
    fn a_checksum_that_does_not_match_is_refused() {
        let ctx = Arc::new(Context::new());

        for (input, expected) in [
            (format!("addr({ADDRESS})#qqqqqqqq"), "does not match"),
            (
                format!("addr({ADDRESS})#short"),
                "Expected 8 character checksum",
            ),
            (
                format!("addr({ADDRESS})#aaaaaaaa#bbbbbbbb"),
                "Multiple '#' symbols",
            ),
        ] {
            let error = getdescriptorinfo(&ctx, &json!([input.clone()]))
                .err()
                .unwrap_or_else(|| panic!("`{input}` must be refused"));
            assert_eq!(error.code(), RpcError::CORE_NOT_FOUND, "for `{input}`");
            assert!(
                error.to_string().contains(expected),
                "`{input}` must say why: got {error}"
            );
        }
    }

    #[test]
    fn getdescriptorinfo_does_not_require_a_checksum() {
        let ctx = Arc::new(Context::new());
        let result = getdescriptorinfo(&ctx, &json!([format!("addr({ADDRESS})")]))
            .unwrap_or_else(|err| panic!("a bare descriptor must be analysed: {err}"));
        let Some(canonical) = result.get("descriptor").and_then(JsonValueTrait::as_str) else {
            panic!("descriptor missing: {result:?}");
        };
        assert!(
            canonical.starts_with(&format!("addr({ADDRESS})#")),
            "the canonical form carries its own checksum: {canonical}"
        );
    }

    #[test]
    fn the_canonical_descriptor_carries_its_own_checksum() {
        let ctx = Arc::new(Context::new());
        let result = getdescriptorinfo(&ctx, &json!([format!("addr({ADDRESS})")]))
            .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));

        let Some(canonical) = result.get("descriptor").and_then(JsonValueTrait::as_str) else {
            panic!("descriptor missing: {result:?}");
        };
        let Some((body, sum)) = canonical.rsplit_once('#') else {
            panic!("the canonical form must carry a checksum: {canonical}");
        };
        assert_eq!(body, format!("addr({ADDRESS})"));
        assert_eq!(sum.len(), 8);

        let derived = deriveaddresses(&ctx, &json!([canonical]))
            .unwrap_or_else(|err| panic!("the canonical form must be usable as-is: {err}"));
        assert_eq!(derived, json!([ADDRESS]));
    }

    #[test]
    fn an_address_descriptor_is_not_solvable() {
        let ctx = Arc::new(Context::new());
        let result = getdescriptorinfo(&ctx, &json!([format!("addr({ADDRESS})")]))
            .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));

        assert_eq!(
            result.get("issolvable").and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        assert_eq!(
            result.get("isrange").and_then(JsonValueTrait::as_bool),
            Some(false)
        );
    }

    #[test]
    fn a_key_descriptor_is_solvable() {
        let ctx = Arc::new(Context::new());
        let descriptor = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
        let result = getdescriptorinfo(&ctx, &json!([descriptor]))
            .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));

        assert_eq!(
            result.get("issolvable").and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        assert_eq!(
            result
                .get("hasprivatekeys")
                .and_then(JsonValueTrait::as_bool),
            Some(false),
            "a public key is not a private one"
        );
    }

    #[test]
    fn a_private_key_is_reported_and_not_echoed_back() {
        let ctx = Arc::new(Context::new());
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let with_key = format!("wpkh({xprv}/0/0)");
        let result = getdescriptorinfo(&ctx, &json!([with_key]))
            .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));

        assert_eq!(
            result
                .get("hasprivatekeys")
                .and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        let Some(canonical) = result.get("descriptor").and_then(JsonValueTrait::as_str) else {
            panic!("descriptor missing: {result:?}");
        };
        assert!(
            !canonical.contains(xprv),
            "the private key must not come back out: {canonical}"
        );
        assert!(
            canonical.contains("xpub"),
            "the canonical form carries the public key: {canonical}"
        );
    }

    #[test]
    fn a_descriptor_that_does_not_parse_is_refused() {
        let ctx = Arc::new(Context::new());
        let error = getdescriptorinfo(&ctx, &json!(["addr(x)"]))
            .err()
            .unwrap_or_else(|| panic!("addr(x) is not an address"));
        assert_eq!(error.code(), RpcError::CORE_NOT_FOUND, "{error:?}");
    }

    #[test]
    fn combo_is_canonicalized_and_private_keys_are_redacted() {
        let ctx = Arc::new(Context::new());
        let key = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
        let result = getdescriptorinfo(&ctx, &json!([format!("combo({key})")]))
            .unwrap_or_else(|err| panic!("getdescriptorinfo failed: {err}"));
        assert!(
            result
                .get("descriptor")
                .and_then(JsonValueTrait::as_str)
                .is_some_and(|descriptor| descriptor.starts_with(&format!("combo({key})#")))
        );
        assert_eq!(
            result
                .get("hasprivatekeys")
                .and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        assert_eq!(
            result.get("issolvable").and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        assert_eq!(
            result.get("isrange").and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        assert!(
            result.get("multipath_expansion").is_none(),
            "single-path combo must omit multipath_expansion: {result:?}"
        );

        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let private = getdescriptorinfo(&ctx, &json!([format!("combo({xprv}/0/0)")]))
            .unwrap_or_else(|err| panic!("combo with an xprv must parse: {err}"));
        assert_eq!(
            private
                .get("hasprivatekeys")
                .and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        let Some(canonical) = private.get("descriptor").and_then(JsonValueTrait::as_str) else {
            panic!("descriptor missing: {private:?}");
        };
        assert!(
            !canonical.contains(xprv),
            "the private key must not come back out: {canonical}"
        );
        assert!(
            canonical.starts_with(&format!("combo({xpub}/0/0)#")),
            "the canonical form is the public combo: {canonical}"
        );
    }

    #[test]
    fn checksummed_combo_is_analysed() {
        let ctx = Arc::new(Context::new());
        let key = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
        let bare = format!("combo({key})");
        let checksum =
            descriptor_checksum(&bare).unwrap_or_else(|| panic!("{bare} must have a checksum"));

        let with = getdescriptorinfo(&ctx, &json!([format!("{bare}#{checksum}")]))
            .unwrap_or_else(|err| panic!("checksummed combo must analyse: {err}"));
        let without = getdescriptorinfo(&ctx, &json!([bare]))
            .unwrap_or_else(|err| panic!("bare combo must analyse: {err}"));
        assert_eq!(without, with);
    }

    #[test]
    fn combo_multipath_is_expanded() {
        let ctx = Arc::new(Context::new());
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let result = getdescriptorinfo(&ctx, &json!([format!("combo({xpub}/<0;1>/*)")]))
            .unwrap_or_else(|err| panic!("multipath combo must parse: {err}"));
        let Some(canonical) = result.get("descriptor").and_then(JsonValueTrait::as_str) else {
            panic!("descriptor missing: {result:?}");
        };
        assert!(
            canonical.starts_with(&format!("combo({xpub}/0/*)#")),
            "the first expansion is canonical: {canonical}"
        );
        let Some(expansions) = result.get("multipath_expansion").and_then(Value::as_array) else {
            panic!("multipath combo must report expansions: {result:?}");
        };
        assert_eq!(expansions.len(), 2, "{result:?}");
        let Some(first) = expansions.first().and_then(JsonValueTrait::as_str) else {
            panic!("first expansion missing: {result:?}");
        };
        let Some(second) = expansions.get(1).and_then(JsonValueTrait::as_str) else {
            panic!("second expansion missing: {result:?}");
        };
        assert_eq!(first, canonical);
        assert!(
            second.starts_with(&format!("combo({xpub}/1/*)#")),
            "second path in specifier order: {second}"
        );
        assert_eq!(
            result.get("isrange").and_then(JsonValueTrait::as_bool),
            Some(true)
        );
    }

    #[test]
    fn combo_rejects_a_wif_from_another_network() {
        let ctx = Arc::new(Context::new());
        let wif = testnet_compressed_wif();
        let error = getdescriptorinfo(&ctx, &json!([format!("combo({wif})")]))
            .err()
            .unwrap_or_else(|| panic!("a testnet WIF must not analyse on mainnet"));
        assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
        assert!(
            error.to_string().contains("test network"),
            "the refusal must say which network the key is for: {error}"
        );
    }

    #[test]
    fn combo_rejects_a_testnet_extended_key_on_mainnet() {
        let ctx = Arc::new(Context::new());
        let tpub = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B";
        let error = getdescriptorinfo(&ctx, &json!([format!("combo({tpub}/0/*)")]))
            .err()
            .unwrap_or_else(|| panic!("a testnet xpub must not analyse on mainnet"));
        assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
        assert!(error.to_string().contains("test network"), "got {error}");
    }

    fn testnet_compressed_wif() -> String {
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
        .unwrap_or_else(|err| panic!("secret 1 is valid: {err}"));
        bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Test,
            inner: secret,
        }
        .to_string()
    }
}

#[cfg(test)]
mod deriveaddresses_tests {
    use alloc::sync::Arc;

    use super::*;

    const ADDRESS: &str = "1111111111111111111114oLvT2";

    fn checksummed(descriptor: &str) -> String {
        let Some(checksum) = descriptor_checksum(descriptor) else {
            panic!("the fixture descriptor `{descriptor}` must have a checksum");
        };
        format!("{descriptor}#{checksum}")
    }

    #[test]
    fn an_address_descriptor_derives_its_own_address() {
        let ctx = Arc::new(Context::new());
        let result = deriveaddresses(&ctx, &json!([checksummed(&format!("addr({ADDRESS})"))]))
            .unwrap_or_else(|err| panic!("deriveaddresses failed: {err}"));

        assert_eq!(result, json!([ADDRESS]));
    }

    #[test]
    fn a_range_too_large_to_serve_is_refused_before_any_work() {
        let ctx = Arc::new(Context::new());
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let descriptor = checksummed(&format!("wpkh({xpub}/0/*)"));

        let started = std::time::Instant::now();
        for (range, expected) in [
            (json!([0, 4_294_967_295_u64]), "End of range is too high"),
            (json!([0, 2_147_483_648_u64]), "End of range is too high"),
            (json!([0, 2_147_483_647_u64]), "Range is too large"),
            (json!([0, 1_000_000]), "Range is too large"),
            (json!(1_000_000), "Range is too large"),
        ] {
            let error = deriveaddresses(&ctx, &json!([descriptor.clone(), range.clone()]))
                .err()
                .unwrap_or_else(|| panic!("{range:?} must be refused"));
            assert_eq!(
                error.code(),
                RpcError::CORE_INVALID_PARAMETER,
                "for {range:?}"
            );
            assert!(
                error.to_string().contains(expected),
                "for {range:?}: {error}"
            );
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the refusals must happen before the derivation, not after it"
        );

        let ok = deriveaddresses(&ctx, &json!([descriptor, [10, 12]]))
            .unwrap_or_else(|err| panic!("a modest range must still work: {err}"));
        assert_eq!(ok.as_array().map(sonic_rs::Array::len), Some(3));
    }

    #[test]
    fn a_testnet_key_does_not_derive_mainnet_addresses() {
        let ctx = Arc::new(Context::new());
        let tpub = "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp";
        let descriptor = checksummed(&format!("wpkh({tpub}/0/*)"));

        let error = deriveaddresses(&ctx, &json!([descriptor, [0, 1]]))
            .err()
            .unwrap_or_else(|| panic!("a testnet key must not derive mainnet addresses"));
        assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
        assert!(
            error.to_string().contains("test network"),
            "the refusal must say which network the key is for: {error}"
        );
    }

    #[test]
    fn deriveaddresses_requires_a_checksum() {
        let ctx = Arc::new(Context::new());

        let error = deriveaddresses(&ctx, &json!([format!("addr({ADDRESS})")]))
            .err()
            .unwrap_or_else(|| panic!("a descriptor with no checksum must be refused"));
        assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
        assert!(
            error.to_string().contains("Missing checksum"),
            "got {error}"
        );

        let accepted = deriveaddresses(&ctx, &json!([checksummed(&format!("addr({ADDRESS})"))]))
            .unwrap_or_else(|err| panic!("the same descriptor with a checksum: {err}"));
        assert_eq!(accepted, json!([ADDRESS]));
    }

    #[test]
    fn a_key_descriptor_derives_an_address() {
        let ctx = Arc::new(Context::new());
        let descriptor =
            checksummed("wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)");
        let result = deriveaddresses(&ctx, &json!([descriptor]))
            .unwrap_or_else(|err| panic!("deriveaddresses failed: {err}"));

        let Some(addresses) = result.as_array() else {
            panic!("expected an array: {result:?}");
        };
        assert_eq!(addresses.len(), 1);
        let Some(address) = addresses.first().and_then(JsonValueTrait::as_str) else {
            panic!("expected a string: {result:?}");
        };
        assert!(
            address.starts_with("bc1q"),
            "a mainnet v0 segwit address: {address}"
        );
    }

    #[test]
    fn a_ranged_descriptor_derives_one_address_per_index() {
        let ctx = Arc::new(Context::new());
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let descriptor = checksummed(&format!("wpkh({xpub}/0/*)"));
        let result = deriveaddresses(&ctx, &json!([descriptor, [0, 2]]))
            .unwrap_or_else(|err| panic!("deriveaddresses failed: {err}"));

        let Some(addresses) = result.as_array() else {
            panic!("expected an array: {result:?}");
        };
        assert_eq!(addresses.len(), 3, "0, 1 and 2: {result:?}");
        let distinct: std::collections::BTreeSet<&str> = addresses
            .iter()
            .filter_map(JsonValueTrait::as_str)
            .collect();
        assert_eq!(
            distinct.len(),
            3,
            "each index is its own address: {result:?}"
        );
    }

    #[test]
    fn the_range_argument_must_match_the_descriptor() {
        let ctx = Arc::new(Context::new());
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

        let missing = deriveaddresses(&ctx, &json!([checksummed(&format!("wpkh({xpub}/0/*)"))]))
            .err()
            .unwrap_or_else(|| panic!("a ranged descriptor needs a range"));
        assert_eq!(missing.code(), RpcError::CORE_INVALID_PARAMETER);

        let fixed_key =
            checksummed("wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)");
        for fixed in [fixed_key, checksummed(&format!("addr({ADDRESS})"))] {
            let unwanted = deriveaddresses(&ctx, &json!([fixed.clone(), [0, 2]]))
                .err()
                .unwrap_or_else(|| panic!("a fixed descriptor takes no range: {fixed}"));
            assert_eq!(
                unwanted.code(),
                RpcError::CORE_INVALID_PARAMETER,
                "for {fixed}"
            );
        }
    }

    #[test]
    fn combo_derives_core_regtest_addresses() {
        let mut ctx = Context::new();
        ctx.chain.chain_network = bitcoin_rs_primitives::Network::Regtest;
        let ctx = Arc::new(ctx);
        let tprv = "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK";
        let result = deriveaddresses(&ctx, &json!([checksummed(&format!("combo({tprv}/1/1/0)"))]))
            .unwrap_or_else(|err| panic!("combo must derive: {err}"));
        assert_eq!(
            result,
            json!([
                "mtfUoUax9L4tzXARpw1oTGxWyoogp52KhJ",
                "bcrt1qjqmxmkpmxt80xz4y3746zgt0q3u3ferr34acd5",
                "2NDvEwGfpEqJWfybzpKPHF2XH3jwoQV3D7x"
            ])
        );
    }

    #[test]
    fn combo_uncompressed_derives_only_p2pkh() {
        let ctx = Arc::new(Context::new());
        let key = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
        let combo = deriveaddresses(&ctx, &json!([checksummed(&format!("combo({key})"))]))
            .unwrap_or_else(|err| panic!("uncompressed combo must derive: {err}"));
        let pkh = deriveaddresses(&ctx, &json!([checksummed(&format!("pkh({key})"))]))
            .unwrap_or_else(|err| panic!("pkh of the same key: {err}"));
        assert_eq!(combo, pkh);
        assert_eq!(combo.as_array().map(sonic_rs::Array::len), Some(1));
    }

    #[test]
    fn combo_compressed_derives_the_bip384_address_set() {
        let ctx = Arc::new(Context::new());
        let key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let combo = deriveaddresses(&ctx, &json!([checksummed(&format!("combo({key})"))]))
            .unwrap_or_else(|err| panic!("compressed combo must derive: {err}"));
        let pkh = deriveaddresses(&ctx, &json!([checksummed(&format!("pkh({key})"))]))
            .unwrap_or_else(|err| panic!("pkh: {err}"));
        let wpkh = deriveaddresses(&ctx, &json!([checksummed(&format!("wpkh({key})"))]))
            .unwrap_or_else(|err| panic!("wpkh: {err}"));
        let sh_wpkh = deriveaddresses(&ctx, &json!([checksummed(&format!("sh(wpkh({key}))"))]))
            .unwrap_or_else(|err| panic!("sh(wpkh): {err}"));
        let expected = json!([
            pkh.as_array()
                .and_then(|arr| arr.first())
                .cloned()
                .unwrap_or_else(|| panic!("pkh address")),
            wpkh.as_array()
                .and_then(|arr| arr.first())
                .cloned()
                .unwrap_or_else(|| panic!("wpkh address")),
            sh_wpkh
                .as_array()
                .and_then(|arr| arr.first())
                .cloned()
                .unwrap_or_else(|| panic!("sh(wpkh) address")),
        ]);
        assert_eq!(combo, expected);
    }

    #[test]
    fn combo_range_must_match_and_derives_one_set_per_index() {
        let ctx = Arc::new(Context::new());
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let ranged = checksummed(&format!("combo({xpub}/0/*)"));
        let missing = deriveaddresses(&ctx, &json!([ranged]))
            .err()
            .unwrap_or_else(|| panic!("a ranged combo needs a range"));
        assert_eq!(missing.code(), RpcError::CORE_INVALID_PARAMETER);

        let fixed = checksummed(
            "combo(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
        );
        let unwanted = deriveaddresses(&ctx, &json!([fixed, [0, 1]]))
            .err()
            .unwrap_or_else(|| panic!("a fixed combo takes no range"));
        assert_eq!(unwanted.code(), RpcError::CORE_INVALID_PARAMETER);

        let derived = deriveaddresses(&ctx, &json!([ranged, [0, 1]]))
            .unwrap_or_else(|err| panic!("ranged combo must derive: {err}"));
        let Some(addresses) = derived.as_array() else {
            panic!("expected a flat array: {derived:?}");
        };
        assert_eq!(addresses.len(), 6, "3 addresses × 2 indices: {derived:?}");
        let distinct: std::collections::BTreeSet<&str> = addresses
            .iter()
            .filter_map(JsonValueTrait::as_str)
            .collect();
        assert_eq!(
            distinct.len(),
            6,
            "each script and index is distinct: {derived:?}"
        );
    }

    #[test]
    fn combo_does_not_derive_from_a_testnet_wif_on_mainnet() {
        let ctx = Arc::new(Context::new());
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
        .unwrap_or_else(|err| panic!("secret 1 is valid: {err}"));
        let wif = bitcoin::PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Test,
            inner: secret,
        }
        .to_string();
        let error = deriveaddresses(&ctx, &json!([checksummed(&format!("combo({wif})"))]))
            .err()
            .unwrap_or_else(|| panic!("a testnet WIF must not derive on mainnet"));
        assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
        assert!(error.to_string().contains("test network"), "got {error}");
    }
}

#[cfg(test)]
mod script_decode_tests {
    use super::*;

    #[test]
    fn direct_script_decode_obeys_the_transport_input_budget() {
        let context = Arc::new(Context::new());
        let oversized = "00".repeat(crate::server::MAX_BODY_BYTES / 2 + 1);
        let result = decodescript(&context, &json!([oversized]));
        assert!(
            matches!(result, Err(RpcError::InvalidParameter(message)) if message == "script exceeds the RPC request byte limit")
        );
    }
}
