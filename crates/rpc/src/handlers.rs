use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin_rs_primitives::Txid;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, Value};

use crate::context::Context;
use crate::error::RpcError;

pub(crate) mod chain;
pub(crate) mod mempool;
pub(crate) mod mining;
pub(crate) mod network;
pub(crate) mod tx;
pub(crate) mod util;

/// Enumerates the live registry names in table order.
///
/// Projects from [`crate::registry::REGISTRY`], yielding only rows with a
/// bound dispatch arm. Exposed for the manifest coverage gate
/// (`crates/rpc/tests/manifest_coverage.rs`), which asserts set equality
/// with the shipped manifest rows in both directions.
pub fn live_registry() -> impl Iterator<Item = &'static str> {
    crate::registry::REGISTRY
        .iter()
        .filter(|row| row.handler.is_some())
        .map(|row| row.entry.name)
}

/// JSON-RPC method dispatcher backed by shared node context.
#[derive(Clone, Debug)]
pub struct Handler {
    ctx: Arc<Context>,
}

impl Handler {
    /// Builds a dispatcher over `ctx`.
    #[must_use]
    pub const fn new(ctx: Arc<Context>) -> Self {
        Self { ctx }
    }

    /// Returns the shared context used by the handlers.
    #[must_use]
    pub fn context(&self) -> &Arc<Context> {
        &self.ctx
    }

    /// Dispatches one Bitcoin Core-compatible JSON-RPC method.
    ///
    /// One lookup in [`crate::registry::REGISTRY`] answers both the method
    /// name and its dispatch arm. The registry is generated from the
    /// compatibility manifest, so a row without a dispatch arm is a method
    /// the manifest declares but this build does not ship; it answers
    /// method-not-found like any unknown method.
    ///
    /// PRE: `method` and `params` are the decoded JSON-RPC request fields.
    /// POST: `Ok(response)` from the row's dispatch arm, or the
    ///   method-not-found error when no row or no arm exists for `method`.
    /// INVARIANT: a method that answers is a manifest row, and a manifest
    ///   row with an arm never returns method-not-found.
    pub fn dispatch(&self, method: &str, params: &Value) -> Result<Value, RpcError> {
        let Some(handler) = crate::registry::REGISTRY
            .iter()
            .find(|row| row.entry.name == method)
            .and_then(|row| row.handler)
        else {
            return Err(RpcError::MethodNotFound(method.to_owned()));
        };
        handler(&self.ctx, params)
    }
}

pub(crate) fn ensure_at_most_params(params: &Value, max: usize) -> Result<(), RpcError> {
    if params.is_null() {
        return Ok(());
    }
    let array = params_array(params)?;
    if array.len() > max {
        return Err(RpcError::InvalidParams("too many parameters"));
    }
    Ok(())
}

pub(crate) fn ensure_no_params(params: &Value) -> Result<(), RpcError> {
    if params.is_null() {
        return Ok(());
    }
    let Some(array) = params.as_array() else {
        return Err(RpcError::InvalidParams("params must be an array"));
    };
    if array.is_empty() {
        Ok(())
    } else {
        Err(RpcError::InvalidParams("method does not accept parameters"))
    }
}

pub(crate) fn params_array(params: &Value) -> Result<&sonic_rs::Array, RpcError> {
    params
        .as_array()
        .ok_or(RpcError::InvalidParams("params must be an array"))
}

/// Returns the type name Bitcoin Core 31.1 spells for a JSON value.
fn json_type_name(value: &Value) -> &'static str {
    if value.is_null() {
        "null"
    } else if value.is_boolean() {
        "bool"
    } else if value.is_number() {
        "number"
    } else if value.is_str() {
        "string"
    } else if value.is_array() {
        "array"
    } else {
        "object"
    }
}

/// Builds Core 31.1's type error for a required positional argument.
///
/// PRE: `value` failed the expected-type check for argument `position`.
/// POST: the `InvalidType` (-3) error whose message names the position, the
///   argument label, the value's type, and the expected type, in Core 31.1's
///   `Wrong type passed` shape.
/// INVARIANT: the message is built only from the call's inputs; no state.
pub(crate) fn wrong_type(
    position: usize,
    label: &str,
    value: &Value,
    expected: &str,
) -> RpcError {
    RpcError::InvalidType(format!(
        "Wrong type passed:\n{{\n    \"Position {} ({})\": \"JSON value of type {} is not of expected type {}\"\n}}",
        position,
        label,
        json_type_name(value),
        expected
    ))
}

/// Builds Core 31.1's type error sentence for an unnamed optional argument.
///
/// PRE: `value` failed the expected-type check for an optional argument the
///   dispatcher reads without a declared label.
/// POST: the `InvalidType` (-3) error carrying Core 31.1's bare sentence.
/// INVARIANT: the message is built only from the call's inputs; no state.
pub(crate) fn wrong_type_plain(value: &Value, expected: &str) -> RpcError {
    RpcError::InvalidType(format!(
        "JSON value of type {} is not of expected type {}",
        json_type_name(value),
        expected
    ))
}

/// The argument label Core 31.1 uses, derived from the required-parameter
/// message the call site passes (`"txid is required"` names the txid).
fn label_of(name: &str) -> &str {
    name.strip_suffix(" is required").unwrap_or(name)
}

pub(crate) fn optional_bool(params: &Value, index: usize, default: bool) -> Result<bool, RpcError> {
    let Some(array) = params.as_array() else {
        return Ok(default);
    };
    let Some(value) = array.get(index) else {
        return Ok(default);
    };
    if value.is_null() {
        return Ok(default);
    }
    value
        .as_bool()
        .ok_or_else(|| wrong_type_plain(value, "bool"))
}

pub(crate) fn required_str<'a>(
    params: &'a Value,
    index: usize,
    name: &'static str,
) -> Result<&'a str, RpcError> {
    let value = params_array(params)?
        .get(index)
        .ok_or(RpcError::InvalidParams(name))?;
    value
        .as_str()
        .ok_or_else(|| wrong_type(index + 1, label_of(name), value, "string"))
}

pub(crate) fn required_u64(
    params: &Value,
    index: usize,
    name: &'static str,
) -> Result<u64, RpcError> {
    let value = params_array(params)?
        .get(index)
        .ok_or(RpcError::InvalidParams(name))?;
    value
        .as_u64()
        .ok_or_else(|| wrong_type(index + 1, label_of(name), value, "number"))
}

pub(crate) fn required_i64(
    params: &Value,
    index: usize,
    name: &'static str,
) -> Result<i64, RpcError> {
    let value = params
        .as_array()
        .and_then(|arr| arr.get(index))
        .ok_or(RpcError::InvalidParams(name))?;
    value
        .as_i64()
        .ok_or_else(|| wrong_type(index + 1, label_of(name), value, "number"))
}

/// Parses one transaction id from its 64-character hex encoding.
///
/// PRE: `value` is the parameter string a caller supplied; `label` is the
///   argument name Bitcoin Core 31.1 spells in its `-8` messages
///   (`"parameter 1"` for `getrawtransaction`, the declared name elsewhere).
/// POST: the decoded [`Txid`], or the `InvalidParameter` (-8) error whose
///   message names the length of a wrong-length string or the non-hex
///   content of a right-length one, exactly as Core 31.1 spells them.
/// INVARIANT: a decoded txid round-trips through its lowercase hex Display.
pub(crate) fn parse_txid(value: &str, label: &str) -> Result<Txid, RpcError> {
    if value.len() != 64 {
        return Err(RpcError::InvalidParameter(format!(
            "{label} must be of length 64 (not {}, for '{value}')",
            value.len()
        )));
    }
    Txid::from_str(value).map_err(|_| {
        RpcError::InvalidParameter(format!("{label} must be hexadecimal string (not '{value}')"))
    })
}
#[cfg(test)]
mod registry_tests {
    use alloc::collections::BTreeSet;
    use alloc::sync::Arc;

    use sonic_rs::json;

    use super::{
        Handler, live_registry, optional_bool, parse_txid, required_str, required_u64,
    };
    use crate::context::Context;
    use crate::error::RpcError;
    use crate::manifest::{self, SurfaceKind};
    #[cfg(feature = "zmq")]
    use crate::registry::REGISTRY;

    const POLICY_ABSENCES: &[&str] = &[
        "clearmempool",
        "dumpprivkey",
        "dumpwallet",
        "importprivkey",
        "importwallet",
        "importmulti",
        "sethdseed",
    ];

    fn shipped_rpc_rows() -> impl Iterator<Item = &'static manifest::Entry> {
        manifest::entries_of_kind(SurfaceKind::Rpc).filter(|entry| entry.shipped())
    }

    #[test]
    fn core_method_registry_has_the_expected_surface() {
        let live: BTreeSet<&str> = live_registry().collect();
        let shipped: BTreeSet<&str> = shipped_rpc_rows().map(|entry| entry.name).collect();
        assert_eq!(
            live, shipped,
            "live dispatch registry must equal the shipped manifest rows"
        );
        let handler = Handler::new(Arc::new(Context::new()));
        for entry in shipped_rpc_rows() {
            assert!(
                !matches!(
                    handler.dispatch(entry.name, &json!([])),
                    Err(RpcError::MethodNotFound(_))
                ),
                "{} is listed but not dispatchable",
                entry.name
            );
        }
        for method in POLICY_ABSENCES {
            assert!(matches!(
                handler.dispatch(method, &json!([])),
                Err(RpcError::MethodNotFound(_))
            ));
        }
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn zmq_build_adds_exactly_one_method() {
        assert_eq!(
            REGISTRY
                .iter()
                .filter(|row| row.entry.name == "getzmqnotifications" && row.handler.is_some())
                .count(),
            1
        );
        let handler = Handler::new(Arc::new(Context::new()));
        assert!(!matches!(
            handler.dispatch("getzmqnotifications", &json!([])),
            Err(RpcError::MethodNotFound(_))
        ));
    }

    #[cfg(not(feature = "zmq"))]
    #[test]
    fn non_zmq_build_omits_notification_method() {
        assert!(!live_registry().any(|name| name == "getzmqnotifications"));
        let handler = Handler::new(Arc::new(Context::new()));
        assert!(matches!(
            handler.dispatch("getzmqnotifications", &json!([])),
            Err(RpcError::MethodNotFound(_))
        ));
    }

    // Bitcoin Core 31.1 parameter-error classification, probed against the
    // pinned release: a wrong JSON type is -3 in Core's own words, a
    // correctly typed but unacceptable value is -8, and only shape and
    // arity remain on -32602.
    #[test]
    fn wrong_json_type_answers_core_type_error_text() {
        let params = json!(["abc"]);
        let error = required_u64(&params, 0, "height is required").expect_err("type error");
        assert_eq!(error.code(), RpcError::CORE_INVALID_TYPE);
        assert_eq!(
            error.to_string(),
            "Wrong type passed:\n{\n    \"Position 1 (height)\": \"JSON value of type string is not of expected type number\"\n}"
        );
    }

    #[test]
    fn missing_required_parameter_keeps_the_shape_error() {
        let params = json!([]);
        let error = required_str(&params, 0, "txid is required").expect_err("missing");
        assert_eq!(error.code(), RpcError::INVALID_PARAMS);
        assert_eq!(error.to_string(), "invalid params: txid is required");
    }

    #[test]
    fn optional_boolean_type_error_names_the_type() {
        let params = json!(["ignored", "yes"]);
        let error = optional_bool(&params, 1, true).expect_err("type error");
        assert_eq!(error.code(), RpcError::CORE_INVALID_TYPE);
        assert_eq!(
            error.to_string(),
            "JSON value of type string is not of expected type bool"
        );
    }

    #[test]
    fn txid_parameter_errors_use_core_text() {
        let short = parse_txid("123", "parameter 1").expect_err("short");
        assert_eq!(short.code(), RpcError::CORE_INVALID_PARAMETER);
        assert_eq!(
            short.to_string(),
            "parameter 1 must be of length 64 (not 3, for '123')"
        );
        let non_hex = parse_txid(&"z".repeat(64), "parameter 1").expect_err("non-hex");
        assert_eq!(non_hex.code(), RpcError::CORE_INVALID_PARAMETER);
        assert_eq!(
            non_hex.to_string(),
            format!("parameter 1 must be hexadecimal string (not '{}')", "z".repeat(64))
        );
    }
}
