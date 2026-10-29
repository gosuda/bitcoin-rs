use alloc::borrow::Cow;
use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin_rs_primitives::Txid;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, Value};

use crate::context::Context;
use crate::error::RpcError;

pub(crate) mod chain;
pub(crate) mod deployment;
pub(crate) mod mempool;
pub(crate) mod mining;
pub(crate) mod network;
#[cfg(feature = "pool")]
pub(crate) mod pool;
#[cfg(feature = "silent-payments")]
pub(crate) mod silent_payments;
pub(crate) mod tx;
pub(crate) mod util;
pub(crate) mod wait;

/// Enumerates the live registry names in table order.
pub fn live_registry() -> impl Iterator<Item = &'static str> {
    crate::registry::REGISTRY
        .iter()
        .filter(|row| row.handler.is_some())
        .map(|row| row.entry.name)
}

/// JSON-RPC method dispatcher backed by shared node context.
#[derive(Debug)]
pub struct Handler {
    ctx: Arc<Context>,
    stop: Arc<core::sync::atomic::AtomicBool>,
    blocking_requests: parking_lot::Mutex<(usize, usize)>,
}

impl Handler {
    #[must_use]
    pub fn new(ctx: Arc<Context>) -> Self {
        Self {
            ctx,
            stop: Arc::new(core::sync::atomic::AtomicBool::new(false)),
            blocking_requests: parking_lot::Mutex::new((0, 16)),
        }
    }

    /// Admits blocking calls on all but one of the connections a single
    /// source may hold, so its own blocking calls never take its last
    /// connection. A full pool still refuses every source.
    pub(crate) fn configure_blocking_admission(&self, source_connections: usize) {
        self.blocking_requests.lock().1 = source_connections.saturating_sub(1);
    }

    pub(crate) fn reserve_blocking_request(&self) -> Result<BlockingRequest<'_>, RpcError> {
        let mut budget = self.blocking_requests.lock();
        if budget.0 >= budget.1 {
            return Err(RpcError::Misc(
                "RPC blocking request limit reached".to_owned(),
            ));
        }
        budget.0 += 1;
        Ok(BlockingRequest(self))
    }

    pub(crate) fn is_stopping(&self) -> bool {
        self.stop.load(core::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn stop(&self) {
        self.stop.store(true, core::sync::atomic::Ordering::Release);
        if let Some(owner) = &self.ctx.chain.active_tip_wait {
            owner.wake_waiters();
        }
    }

    #[must_use]
    pub fn context(&self) -> &Arc<Context> {
        &self.ctx
    }

    pub fn dispatch(&self, method: &str, params: &Value) -> Result<Value, RpcError> {
        let row = crate::registry::REGISTRY
            .iter()
            .find(|row| row.entry.name == method);
        let Some((row, handler)) = row.and_then(|row| row.handler.map(|handler| (row, handler)))
        else {
            return Err(RpcError::MethodNotFound(method.to_owned()));
        };
        let _blocking = row
            .execution
            .is_blocking(params)
            .then(|| {
                self.reserve_blocking_request().map_err(|error| {
                    if matches!(row.execution, crate::registry::Execution::Scan)
                        && self.ctx.chain.utxo.scan_progress().is_some()
                    {
                        RpcError::InvalidParameter(
                            bitcoin_rs_utxo::scan::UtxoScanError::InProgress.to_string(),
                        )
                    } else {
                        error
                    }
                })
            })
            .transpose()?;
        let _active = self.ctx.active_calls.begin(method);
        let cancellation = bitcoin_rs_chain::LatchReader::new(Arc::clone(&self.stop));
        match handler {
            crate::registry::Dispatch::Immediate(handler) => handler(&self.ctx, params),
            crate::registry::Dispatch::Cancellable(handler) => {
                handler(&self.ctx, params, &cancellation)
            }
        }
    }
}

pub(crate) struct BlockingRequest<'a>(&'a Handler);

impl Drop for BlockingRequest<'_> {
    fn drop(&mut self) {
        self.0.blocking_requests.lock().0 -= 1;
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

/// Binds a method's ordinary named arguments to its positional order.
///
/// Core's optional `args` prefix fills only the initial unnamed positions; explicit
/// nulls still count as named arguments. Omitted trailing arguments stay omitted, and a
/// non-array `args` value is consumed without effect. Method owners retain arity, type,
/// default, and value validation.
pub(crate) fn bind_named_params<'a>(
    params: &'a Value,
    names: &[&str],
) -> Result<Cow<'a, Value>, RpcError> {
    if params.is_array() {
        return Ok(Cow::Borrowed(params));
    }
    if params.is_null() {
        return Ok(Cow::Owned(Value::from(Vec::<Value>::new())));
    }
    let object = params
        .as_object()
        .ok_or(RpcError::InvalidParams("params must be an array or object"))?;
    ensure_unique_named_params(object)?;

    let mut values = Vec::new();
    let mut first_named = None;
    for (index, name) in names.iter().enumerate() {
        if let Some(value) = params.get(*name) {
            first_named.get_or_insert((index, *name));
            values.resize(index, Value::new_null());
            values.push(value.clone());
        }
    }
    if let Some(args) = params.get("args").and_then(|value| value.as_array()) {
        if let Some((index, name)) = first_named
            && args.len() > index
        {
            return Err(RpcError::InvalidParameter(format!(
                "Parameter {name} specified twice both as positional and named argument"
            )));
        }
        let mut prefixed = args.to_vec();
        prefixed.extend(values.into_iter().skip(args.len()));
        values = prefixed;
    }
    if let Some(key) = object
        .iter()
        .map(|(key, _)| key)
        .filter(|key| *key != "args" && !names.contains(key))
        .min()
    {
        return Err(RpcError::InvalidParameter(format!(
            "Unknown named parameter {key}"
        )));
    }
    Ok(Cow::Owned(Value::from(values)))
}

/// Validate original object keys before a method folds named-only options.
pub(crate) fn ensure_unique_named_params(object: &sonic_rs::Object) -> Result<(), RpcError> {
    let mut seen = hashbrown::HashSet::new();
    for (key, _) in object {
        if !seen.insert(key) {
            return Err(RpcError::InvalidParameter(format!(
                "Parameter {key} specified multiple times"
            )));
        }
    }
    Ok(())
}

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

fn wrong_type(position: usize, label: &str, value: &Value, expected: &str) -> RpcError {
    RpcError::InvalidType(format!(
        "Wrong type passed:\n{{\n    \"Position {} ({})\": \"JSON value of type {} is not of expected type {}\"\n}}",
        position,
        label,
        json_type_name(value),
        expected
    ))
}

pub(crate) fn wrong_type_plain(value: &Value, expected: &str) -> RpcError {
    RpcError::InvalidType(format!(
        "JSON value of type {} is not of expected type {}",
        json_type_name(value),
        expected
    ))
}

fn label_of(name: &str) -> &str {
    name.strip_suffix(" is required")
        .or_else(|| name.strip_suffix(" must be a string"))
        .unwrap_or(name)
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
    if !value.is_number() {
        return Err(wrong_type(index + 1, label_of(name), value, "number"));
    }
    value
        .as_u64()
        .ok_or_else(|| RpcError::InvalidParameter(format!("{} is out of range", label_of(name))))
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
    if !value.is_number() {
        return Err(wrong_type(index + 1, label_of(name), value, "number"));
    }
    value
        .as_i64()
        .ok_or_else(|| RpcError::InvalidParameter(format!("{} is out of range", label_of(name))))
}

pub(crate) fn parse_txid(value: &str, label: &str) -> Result<Txid, RpcError> {
    if value.len() != 64 {
        return Err(RpcError::InvalidParameter(format!(
            "{label} must be of length 64 (not {}, for '{value}')",
            value.len()
        )));
    }
    Txid::from_str(value).map_err(|_| {
        RpcError::InvalidParameter(format!(
            "{label} must be hexadecimal string (not '{value}')"
        ))
    })
}
#[cfg(test)]
mod registry_tests;
