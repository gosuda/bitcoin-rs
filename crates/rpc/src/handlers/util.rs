use alloc::sync::Arc;
use alloc::vec::Vec;
use core::str::FromStr as _;
use std::sync::OnceLock;
use std::time::Instant;

use miniscript::DefiniteDescriptorKey;
use miniscript::Descriptor as MiniscriptDescriptor;
use miniscript::ForEachKey as _;
use miniscript::descriptor::{DescriptorPublicKey, DescriptorSecretKey, KeyMap};
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

pub(crate) fn getdescriptorinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let descriptor = required_str(params, 0, "descriptor is required")?;
    // Optional here, as in Core: `Parse` is called without `require_checksum`,
    // so a bare descriptor is analysed and one carrying a checksum has it
    // checked.
    let checksum = checked_checksum(descriptor, ChecksumRequirement::Optional)?;

    let info = analyse(descriptor, convert::bitcoin_network(ctx.chain_network))
        .map_err(descriptor_error)?;

    typed_to_sonic_omitting_nulls(&v31::GetDescriptorInfo {
        // The canonical form comes from the parse, so a descriptor handed to this
        // call with an `xprv` in it does not get one back.
        //
        // It carries its own checksum, as Core's does: `DescriptorImpl::ToString`
        // ends in `return AddChecksum(ret)`. That checksum is of the *canonical*
        // string and the `checksum` field below is of the *input*, which is not a
        // duplication -- the two differ whenever the parse rewrites anything, an
        // `xprv` replaced by its `xpub` most obviously. A caller copying the
        // canonical form back out needs the one that matches what they copied.
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
    // Core passes `require_checksum = true` here, and only here. These
    // addresses are what someone will send money to; a mistyped descriptor
    // derives perfectly good addresses that nobody holds the keys for, and the
    // checksum is the only thing between a typo and that.
    let _checksum = checked_checksum(descriptor, ChecksumRequirement::Required)?;
    let range = array
        .get(1)
        .filter(|value| !value.is_null())
        .map(parse_derivation_range)
        .transpose()?;

    let expansions = derive_descriptor_addresses(
        descriptor,
        convert::bitcoin_network(ctx.chain_network),
        range,
    )
    .map_err(descriptor_error)?;

    // Core returns a flat array for a single-path descriptor and an array per
    // expansion for a multipath one.
    match <[Vec<String>; 1]>::try_from(expansions) {
        Ok([single]) => typed_to_sonic(&v31::DeriveAddresses(single)),
        Err(many) => typed_to_sonic(&v31::DeriveAddressesMultipath(
            many.into_iter().map(v31::DeriveAddresses).collect(),
        )),
    }
}

/// Maps a descriptor failure onto the code Bitcoin Core answers it with.
///
/// A descriptor that does not parse is `-5`; a range that does not match a
/// descriptor that parsed fine is `-8`. They are different questions and Core
/// keeps them apart, so a client can tell "I sent you nonsense" from "I asked
/// the wrong thing about something valid".
fn descriptor_error(error: DescriptorError) -> RpcError {
    match error {
        DescriptorError::Range(message) => RpcError::InvalidParameter(message.to_owned()),
        DescriptorError::Parse(message) => RpcError::InvalidAddressOrKey(message),
    }
}

/// A canonical descriptor with its own checksum attached, as Core returns it.
///
/// Falls back to the bare form if the payload somehow carries a character
/// outside BIP380's input charset. That cannot happen for a string this node
/// just produced from a parsed descriptor, and returning a descriptor without a
/// checksum is a better failure than refusing to answer about one that parsed.
fn with_checksum(canonical: &str) -> String {
    descriptor_checksum(canonical)
        .map_or_else(|| canonical.to_owned(), |sum| format!("{canonical}#{sum}"))
}

/// Whether a descriptor must carry a checksum to be accepted.
///
/// Core decides this per call site, and the two answers are not arbitrary.
/// `getdescriptorinfo` analyses whatever it is handed, so a checksum is
/// optional there. `deriveaddresses` turns a descriptor into addresses someone
/// will send money to, so Core passes `require_checksum = true` -- a mistyped
/// descriptor derives perfectly good addresses that nobody holds the keys for,
/// and the checksum is the only thing standing between a typo and that.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChecksumRequirement {
    /// Accept a descriptor with no checksum; verify one that is present.
    Optional,
    /// Refuse a descriptor with no checksum.
    Required,
}

/// Verifies a descriptor's checksum and returns the computed one.
///
/// Bitcoin Core's `CheckChecksum` in `script/descriptor.cpp`, rule for rule.
/// The previous implementation split the text on its last `#` and threw the
/// supplied checksum away, which meant a *wrong* checksum was accepted and
/// silently replaced with the right one in the response. The checksum exists to
/// catch a mistyped descriptor; discarding it defeats the entire mechanism, and
/// the caller is told their typo is fine.
///
/// The three refusals, in Core's order:
///
/// - more than one `#`, which is a malformed descriptor rather than a
///   descriptor with an odd checksum;
/// - a checksum that is present but not exactly eight characters;
/// - a checksum that does not match the one the payload computes.
fn checked_checksum(
    descriptor: &str,
    requirement: ChecksumRequirement,
) -> Result<String, RpcError> {
    let mut parts = descriptor.split('#');
    let Some(payload) = parts.next() else {
        return Err(RpcError::InvalidAddressOrKey(
            "Invalid characters in payload".to_owned(),
        ));
    };
    let supplied = parts.next();
    if parts.next().is_some() {
        return Err(RpcError::InvalidAddressOrKey(
            "Multiple '#' symbols".to_owned(),
        ));
    }
    if supplied.is_none() && requirement == ChecksumRequirement::Required {
        return Err(RpcError::InvalidAddressOrKey("Missing checksum".to_owned()));
    }
    if let Some(supplied) = supplied
        && supplied.len() != 8
    {
        return Err(RpcError::InvalidAddressOrKey(format!(
            "Expected 8 character checksum, not {} characters",
            supplied.len()
        )));
    }

    let computed = descriptor_checksum(payload)
        .ok_or_else(|| RpcError::InvalidAddressOrKey("Invalid characters in payload".to_owned()))?;
    if let Some(supplied) = supplied
        && supplied != computed
    {
        return Err(RpcError::InvalidAddressOrKey(format!(
            "Provided checksum '{supplied}' does not match computed checksum '{computed}'"
        )));
    }
    Ok(computed)
}

/// Bitcoin Core's `ParseDescriptorRange`: an end, or an inclusive `[begin,end]`.
fn parse_derivation_range(value: &Value) -> Result<(u32, u32), RpcError> {
    const RANGE_TOO_LARGE: &str = "Range is too large";

    if let Some(end) = value.as_u64() {
        let end = u32::try_from(end)
            .map_err(|_| RpcError::InvalidParameter(RANGE_TOO_LARGE.to_owned()))?;
        bound_derivation_work(0, end)?;
        return Ok((0, end));
    }
    let Some(pair) = value.as_array().filter(|pair| pair.len() == 2) else {
        return Err(RpcError::InvalidParameter(
            "Range must be specified as end or as [begin,end]".to_owned(),
        ));
    };
    let bound = |index: usize| -> Result<u32, RpcError> {
        pair.get(index)
            .and_then(JsonValueTrait::as_u64)
            .ok_or_else(|| {
                RpcError::InvalidParameter("Range should be greater or equal than 0".to_owned())
            })
            .and_then(|value| {
                u32::try_from(value)
                    .map_err(|_| RpcError::InvalidParameter(RANGE_TOO_LARGE.to_owned()))
            })
    };
    let begin = bound(0)?;
    let end = bound(1)?;
    if end < begin {
        return Err(RpcError::InvalidParameter(
            "Range specified as [begin,end] must not have begin after end".to_owned(),
        ));
    }
    bound_derivation_work(begin, end)?;
    Ok((begin, end))
}

/// Core's ceiling on how much work one derive request may ask for.
///
/// `ParseDescriptorRange` in `rpc/util.cpp` refuses `high >= low + 1000000`.
/// Without it `[0, 4294967295]` is a legal request that derives four billion
/// addresses and holds every one of them in memory before answering -- an
/// unauthenticated caller turning one JSON object into an out-of-memory kill.
/// The refusal has to happen before the work starts, which is why it lives in
/// the parser rather than in the loop.
const MAX_DERIVATION_COUNT: u32 = 1_000_000;

/// Core's ceiling on the index itself: `(high >> 31) != 0` is refused, so the
/// top bit is reserved and the largest derivable index is `2^31 - 1`. That is
/// BIP32's unhardened range, and an index above it is not a large request but
/// an impossible one.
const MAX_DERIVATION_INDEX: u32 = (1 << 31) - 1;

fn bound_derivation_work(begin: u32, end: u32) -> Result<(), RpcError> {
    if end > MAX_DERIVATION_INDEX {
        return Err(RpcError::InvalidParameter(
            "End of range is too high".to_owned(),
        ));
    }
    // Core compares `high >= low + 1000000` on `int64_t`, so the sum cannot
    // wrap there; here both are `u32` and it can, which would turn the ceiling
    // into a floor. Widened rather than saturated for that reason.
    if u64::from(end) >= u64::from(begin).saturating_add(u64::from(MAX_DERIVATION_COUNT)) {
        return Err(RpcError::InvalidParameter("Range is too large".to_owned()));
    }
    Ok(())
}

/// Returns the payload inside an `addr(...)` descriptor, if `payload` is one.
pub(crate) fn strip_addr_wrapper(payload: &str) -> Option<&str> {
    let stripped = payload.strip_prefix("addr(")?;
    let stripped = stripped.strip_suffix(')')?;
    Some(stripped)
}

// ---------------------------------------------------------------------------
// Descriptor analysis and derivation (ported from the removed wallet crate).
// ---------------------------------------------------------------------------

/// What `getdescriptorinfo` reports about a descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DescriptorInfo {
    /// Canonical form, with private keys replaced by their public counterparts.
    ///
    /// For a multipath descriptor this is the first expansion, as Bitcoin Core
    /// documents.
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

/// Errors from descriptor analysis or derivation.
enum DescriptorError {
    /// The text is not a descriptor.
    Parse(String),
    /// The derivation range does not match the descriptor.
    Range(&'static str),
}

impl core::fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parse(message) => write!(f, "{message}"),
            Self::Range(message) => write!(f, "{message}"),
        }
    }
}

/// Analyses a descriptor without keeping anything private it carried.
///
/// The returned `canonical` form is derived from the parsed descriptor, whose
/// keys are public by construction: `parse_descriptor` hands the private key
/// material back separately, and this function keeps only the fact that there
/// was some. Echoing the caller's text back would return an `xprv` to whoever
/// asked, which is the one thing this call must not do.
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
        // `addr()` and `raw()` name an output without saying how to spend it,
        // so miniscript does not model them at all. They are still descriptors,
        // and Core reports them as the unsolvable ones they are rather than
        // refusing the question -- but it still checks that what is inside the
        // brackets is an address or a script, and so does this.
        Err(error) => match parse_unspendable(strip_checksum(text)) {
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
    let body = strip_checksum(text);
    if let Some(key) = body
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

/// A parsed `combo(KEY)`, using a single `pkh(KEY)` parse for every later step.
///
/// miniscript has no `combo` variant — BIP 384 is a set of scripts, not one —
/// so the key is parsed through `pkh(...)` once and reused for canonicalization,
/// private-key detection, network checks, and address derivation.
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
        // Single-path descriptors must leave this empty so the RPC omits
        // `multipathexpansion`, matching Core and the documented response.
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

/// Derives the addresses a descriptor describes.
///
/// The outer vector is one entry per multipath expansion, in specifier order;
/// a single-path descriptor yields exactly one. `range` is inclusive at both
/// ends, matching Bitcoin Core.
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

    // An `addr()` or `raw()` descriptor has exactly one output and no range.
    if let Some(unspendable) = parse_unspendable(strip_checksum(text)) {
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

/// BIP 384 / Core `combo(KEY)`: P2PKH, and for a compressed key also P2WPKH
/// and P2SH-P2WPKH. Bare P2PK has no address and is skipped, as Core's
/// `ExtractDestination` does in `DeriveAddresses`.
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

/// Refuses a descriptor whose extended keys belong to another network.
///
/// Bitcoin Core never reaches this check because it cannot: `DecodeExtPubKey`
/// resolves the version bytes against the running chain's Base58 prefix, so a
/// `tpub` on mainnet fails to decode and the descriptor never parses.
/// rust-bitcoin decodes both prefixes into the same type and keeps the network
/// as a field, so the descriptor parses fine and the mismatch survives to
/// derivation -- where `address(network)` re-encodes the key with *this*
/// network's prefix and hands back a `bc1...` address for a testnet key.
///
/// That address is well-formed, and nobody holds its private key. Someone
/// checking the descriptor by eye sees mainnet addresses and has no way to tell.
/// So the check is here rather than absent, and it runs before any derivation.
///
/// `NetworkKind` is the right granularity: BIP32 has two prefix sets, one for
/// mainnet and one shared by every test network, so a signet key and a testnet
/// key are genuinely indistinguishable and refusing between them would refuse
/// something valid.
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
            // A bare public key carries no network. Core does not check one
            // either -- there is nothing in the encoding to check.
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

/// WIF and other secret keys keep their network on the `KeyMap` that
/// `parse_descriptor` returns, not on the public descriptor. A Single public
/// key is networkless, so a testnet WIF would otherwise pass
/// [`ensure_keys_match_network`] on a mainnet node.
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

/// A descriptor that names an output without saying how to spend it.
enum Unspendable {
    /// `addr(<address>)`.
    Address(bitcoin::Address<bitcoin::address::NetworkUnchecked>),
    /// `raw(<script hex>)`.
    Raw(bitcoin::ScriptBuf),
}

impl Unspendable {
    /// The descriptor re-encoded from what was parsed, not echoed back.
    fn canonical(&self) -> String {
        match self {
            Self::Address(address) => format!("addr({})", address.clone().assume_checked()),
            Self::Raw(script) => format!("raw({})", script.to_hex_string()),
        }
    }

    /// The address this output pays to, when it has one.
    fn address(&self, network: bitcoin::Network) -> Result<String, DescriptorError> {
        match self {
            Self::Address(address) => address
                .clone()
                .require_network(network)
                .map(|address| address.to_string())
                .map_err(|error| DescriptorError::Parse(error.to_string())),
            // Core's `ExtractDestination`: a raw script only has an address if
            // it is one of the standard forms.
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

/// Recognises `addr()` and `raw()`, and checks what is inside the brackets.
///
/// `None` means the text is not one of these two forms at all -- the caller
/// should report whatever the real descriptor parser said about it. `Some(Err)`
/// means it is one of them and the contents are not valid, which is a rejection
/// in its own right rather than a reason to fall through.
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

/// Drops a trailing `#checksum`, which is not part of the descriptor body.
fn strip_checksum(text: &str) -> &str {
    text.rsplit_once('#').map_or(text, |(body, _)| body)
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
        // All chars should be in the bech32 charset.
        for ch in checksum.chars() {
            assert!(
                BIP380_CHECKSUM_CHARSET.iter().any(|b| char::from(*b) == ch),
                "checksum char {ch} not in bech32 charset"
            );
        }
    }

    /// The BIP380 vector, so the checksum is not certified by its own output.
    ///
    /// Every other test here compares this implementation against itself. This
    /// one compares it against the specification: the descriptor and checksum
    /// are the worked example in BIP380, and Core answers the same eight
    /// characters for it.
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

        // And the same descriptor with its checksum attached is accepted.
        let with_checksum = getdescriptorinfo(&ctx, &json!([format!("{DESCRIPTOR}#{CHECKSUM}")]))
            .unwrap_or_else(|err| panic!("a correct checksum must be accepted: {err}"));
        assert_eq!(
            with_checksum
                .get("checksum")
                .and_then(JsonValueTrait::as_str),
            Some(CHECKSUM)
        );
    }

    /// A checksum that does not match is refused, not replaced.
    ///
    /// This used to split the text on its last `#`, throw the supplied checksum
    /// away, and answer with a freshly computed one -- so a caller who mistyped
    /// a descriptor was told it was fine and handed a different descriptor than
    /// the one they meant. Catching that typo is the checksum's entire purpose.
    ///
    /// Core's three refusals, from `CheckChecksum` in `script/descriptor.cpp`,
    /// each with the message Core gives.
    #[test]
    fn a_checksum_that_does_not_match_is_refused() {
        let ctx = Arc::new(Context::new());

        for (input, expected) in [
            // Right length, wrong value.
            (format!("addr({ADDRESS})#qqqqqqqq"), "does not match"),
            // Present but not eight characters.
            (
                format!("addr({ADDRESS})#short"),
                "Expected 8 character checksum",
            ),
            // More than one `#` is a malformed descriptor, not an odd checksum.
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

    /// A descriptor with no checksum is still analysed.
    ///
    /// Core calls `Parse` without `require_checksum` here, so the field is
    /// optional -- unlike `deriveaddresses`, where it is not. The two call
    /// sites differ on purpose and this pins that they still do.
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

    /// The canonical descriptor carries a checksum, as Core's does.
    ///
    /// `DescriptorImpl::ToString` ends in `return AddChecksum(ret)`, so every
    /// descriptor Core hands back is ready to be pasted into the next call.
    /// This returned the bare form, so a caller copying it out got something
    /// `deriveaddresses` then refuses for having no checksum.
    ///
    /// The checksum on the canonical form is of the *canonical* string, and the
    /// separate `checksum` field is of the *input*. They differ whenever the
    /// parse rewrites anything, which is what the second half checks.
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

        // Round trip: what comes out must be accepted by the call that demands
        // a checksum, which is the whole point of putting one there.
        let derived = deriveaddresses(&ctx, &json!([canonical]))
            .unwrap_or_else(|err| panic!("the canonical form must be usable as-is: {err}"));
        assert_eq!(derived, json!([ADDRESS]));
    }

    /// A descriptor that names an output cannot produce a spend for it.
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

    /// A descriptor with keys in it *is* solvable, and this used to say no.
    ///
    /// `issolvable` was hardcoded `false`, so every descriptor -- including one
    /// carrying the key needed to spend -- reported that it could not be spent.
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

    /// A private key is reported as one, and is not handed back.
    ///
    /// `hasprivatekeys` was hardcoded `false`. Someone checking whether a
    /// descriptor they were about to share carried their key was told it did
    /// not -- and the response echoed the descriptor, key included.
    #[test]
    fn a_private_key_is_reported_and_not_echoed_back() {
        let ctx = Arc::new(Context::new());
        // BIP32 test vector 1, master private key.
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

    /// Text that is not a descriptor is refused with Core's code.
    #[test]
    fn a_descriptor_that_does_not_parse_is_refused() {
        let ctx = Arc::new(Context::new());
        let error = getdescriptorinfo(&ctx, &json!(["addr(x)"]))
            .err()
            .unwrap_or_else(|| panic!("addr(x) is not an address"));
        assert_eq!(error.code(), RpcError::CORE_NOT_FOUND, "{error:?}");
    }

    /// BIP 384 / Core `doc/descriptors.md`: `combo(KEY)` is the top-level
    /// collection of `pk`/`pkh` (and, for a compressed key, `wpkh`/`sh(wpkh)`).
    ///
    /// A single-path combo must omit `multipathexpansion`. A private key is
    /// reported and replaced by its public form, same as Core's
    /// `provider.keys.size() > 0` plus `DescriptorImpl::ToString`.
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

        // BIP32 test vector 1 master private key, so the redaction is against
        // a published vector rather than this function's own output.
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

    /// Core's `getdescriptorinfo` expands a multipath descriptor into one
    /// entry per path and returns the first as `descriptor`.
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

    /// rust-bitcoin decodes both WIF prefixes; Core refuses a WIF whose
    /// version byte is not this chain's. The network lives on the secret in
    /// the keymap, not on the public `Single` key.
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

    /// Same network check as derivation: a testnet extended key is not valid
    /// descriptor info on a mainnet node.
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
    use sonic_rs::JsonContainerTrait as _;

    use super::*;

    const ADDRESS: &str = "1111111111111111111114oLvT2";

    /// `descriptor#checksum`, because this call requires one.
    ///
    /// These tests are about derivation, not about the checksum, so they append
    /// the computed one rather than hard-coding eight characters per fixture.
    /// The checksum's own correctness is pinned against the BIP380 vector in
    /// `descriptor_checksum_tests`, and its enforcement by the refusals there.
    fn checksummed(descriptor: &str) -> String {
        let Some(checksum) = descriptor_checksum(descriptor) else {
            panic!("the fixture descriptor `{descriptor}` must have a checksum");
        };
        format!("{descriptor}#{checksum}")
    }

    /// An `addr()` descriptor derives the address it names.
    #[test]
    fn an_address_descriptor_derives_its_own_address() {
        let ctx = Arc::new(Context::new());
        let result = deriveaddresses(&ctx, &json!([checksummed(&format!("addr({ADDRESS})"))]))
            .unwrap_or_else(|err| panic!("deriveaddresses failed: {err}"));

        assert_eq!(result, json!([ADDRESS]));
    }

    /// A range Core would refuse never starts deriving.
    ///
    /// `ParseDescriptorRange` in `rpc/util.cpp` refuses `high >= low + 1000000`
    /// and any `high` with its top bit set. Without those, `[0, 4294967295]` is
    /// a legal request that derives four billion addresses and holds every one
    /// of them before answering -- one JSON object turning into an
    /// out-of-memory kill. The refusal has to land before the work starts,
    /// which is why it lives in the parser.
    ///
    /// The test asserts it is *fast* as well as refused: a bound checked inside
    /// the loop would also return an error, eventually, having done the damage.
    #[test]
    fn a_range_too_large_to_serve_is_refused_before_any_work() {
        let ctx = Arc::new(Context::new());
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let descriptor = checksummed(&format!("wpkh({xpub}/0/*)"));

        let started = std::time::Instant::now();
        for (range, expected) in [
            // Top bit set: not a large request but an impossible index.
            (json!([0, 4_294_967_295_u64]), "End of range is too high"),
            (json!([0, 2_147_483_648_u64]), "End of range is too high"),
            // `2^31 - 1` is the largest legal *index*, so it clears the check
            // above and trips the size limit instead -- which is the order Core
            // applies them in, and the reason both messages exist.
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

        // One below the ceiling is served, so the bound is a ceiling and not a
        // blanket refusal. Kept small: this is about the boundary being in the
        // right place, and 999,999 derivations would prove it slowly.
        let ok = deriveaddresses(&ctx, &json!([descriptor, [10, 12]]))
            .unwrap_or_else(|err| panic!("a modest range must still work: {err}"));
        assert_eq!(ok.as_array().map(sonic_rs::Array::len), Some(3));
    }

    /// A key from another network does not derive addresses for this one.
    ///
    /// Bitcoin Core never reaches this: `DecodeExtPubKey` resolves the version
    /// bytes against the running chain's Base58 prefix, so a `tpub` on mainnet
    /// fails to decode and the descriptor never parses. rust-bitcoin decodes
    /// both prefixes into one type and keeps the network as a field, so the
    /// descriptor parses and the mismatch survives to derivation -- where
    /// `address(network)` re-encodes the key with *this* network's prefix and
    /// hands back a `bc1...` address for a testnet key.
    ///
    /// That address is well-formed and nobody holds its private key. Someone
    /// checking the descriptor by eye sees mainnet addresses and cannot tell.
    #[test]
    fn a_testnet_key_does_not_derive_mainnet_addresses() {
        // A mainnet context, which is `Context::new()`'s default.
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

    /// A descriptor with no checksum does not derive an address.
    ///
    /// Core passes `require_checksum = true` here and only here, and the reason
    /// is what these addresses are for: someone sends money to them. A mistyped
    /// descriptor derives perfectly good addresses that nobody holds the keys
    /// for, and the checksum is the only thing between a typo and that. This
    /// used to accept the bare descriptor and derive from it.
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

        // The paired acceptance, so the refusal is the missing checksum and not
        // something else about the descriptor.
        let accepted = deriveaddresses(&ctx, &json!([checksummed(&format!("addr({ADDRESS})"))]))
            .unwrap_or_else(|err| panic!("the same descriptor with a checksum: {err}"));
        assert_eq!(accepted, json!([ADDRESS]));
    }

    /// A key descriptor derives a real address, where this used to answer `[]`.
    ///
    /// Every descriptor but `addr()` returned an empty array -- not an error,
    /// an empty answer, which reads as "this descriptor describes no
    /// addresses" rather than "this node did not look".
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

    /// A ranged descriptor derives one address per index, inclusive at both ends.
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

    /// A range is required for a ranged descriptor, and refused for a fixed one.
    #[test]
    fn the_range_argument_must_match_the_descriptor() {
        let ctx = Arc::new(Context::new());
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

        let missing = deriveaddresses(&ctx, &json!([checksummed(&format!("wpkh({xpub}/0/*)"))]))
            .err()
            .unwrap_or_else(|| panic!("a ranged descriptor needs a range"));
        assert_eq!(missing.code(), RpcError::CORE_INVALID_PARAMETER);

        // Both kinds of fixed descriptor: one miniscript parses, and one it
        // does not model at all. They take separate paths to the same refusal.
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

    /// Bitcoin Core `test/functional/rpc_deriveaddresses.py`: `combo(tprv…/1/1/0)`
    /// on regtest yields P2PKH, P2WPKH, and P2SH-P2WPKH. Bare P2PK is skipped.
    #[test]
    fn combo_derives_core_regtest_addresses() {
        let mut ctx = Context::new();
        ctx.chain_network = bitcoin_rs_primitives::Network::Regtest;
        let ctx = Arc::new(ctx);
        // Bitcoin Core `rpc_deriveaddresses.py`.
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

    /// BIP 384: an uncompressed key is only `pk` + `pkh`, so derivation is the
    /// P2PKH address — the same address `pkh(KEY)` produces.
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

    /// A compressed combo is the flat BIP 384 set: `pkh`, `wpkh`, `sh(wpkh)`.
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

    /// Ranged combo uses the same range contract as every other descriptor, and
    /// each index contributes the BIP 384 address set.
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

    /// A testnet WIF combo is refused on mainnet during derivation too.
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
