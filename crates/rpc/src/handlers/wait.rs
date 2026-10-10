//! Core active-tip waits: parameter projection only, no mining dependency.

use alloc::sync::Arc;
use std::borrow::Cow;
use std::time::{Duration, Instant};

use bitcoin_rs_chain::{LatchReader, TipWaitCondition};
use bitcoin_rs_primitives::Hash256;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value, json};

use crate::{RpcError, context::Context};

use super::{bind_named_params, wrong_type};

fn arguments<'a>(
    params: &'a Value,
    names: &[&str],
    required: usize,
    usage: &str,
) -> Result<Cow<'a, Value>, RpcError> {
    let params = bind_named_params(params, names)?;
    let array = params
        .as_array()
        .ok_or(RpcError::InvalidParams("params must be an array or object"))?;
    if array.len() < required || array.len() > names.len() {
        // The code matches Core's RPCHelpMan arity error; the concise usage
        // intentionally omits its generated help body (manifest Deviation).
        return Err(RpcError::Misc(usage.to_owned()));
    }
    let mut errors = Vec::new();
    for (index, value) in array.iter().enumerate() {
        if value.is_null() && index >= required {
            continue;
        }
        let name = names[index];
        let expected = if matches!(name, "blockhash" | "current_tip") {
            "string"
        } else {
            "number"
        };
        if (expected == "string" && !value.is_str()) || (expected == "number" && !value.is_number())
        {
            errors.push(format!("    \"Position {} ({name})\": \"JSON value of type {} is not of expected type {expected}\"", index + 1, super::json_type_name(value)));
        }
    }
    if !errors.is_empty() {
        return Err(RpcError::InvalidType(format!(
            "Wrong type passed:\n{{\n{}\n}}",
            errors.join(",\n")
        )));
    }
    Ok(params)
}

fn integer(value: &Value, position: usize, label: &str) -> Result<i32, RpcError> {
    if !value.is_number() {
        return Err(wrong_type(position, label, value, "number"));
    }
    value
        .as_i64()
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| RpcError::Misc("JSON integer out of range".to_owned()))
}

fn timeout(value: Option<&Value>, position: usize) -> Result<Option<Instant>, RpcError> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let millis = integer(value, position, "timeout")?;
    if millis < 0 {
        return Err(RpcError::Misc("Negative timeout".to_owned()));
    }
    Ok((millis != 0).then(|| Instant::now() + Duration::from_millis(millis.unsigned_abs().into())))
}

fn hash(value: &Value, position: usize, label: &str) -> Result<Hash256, RpcError> {
    let text = value
        .as_str()
        .ok_or_else(|| wrong_type(position, label, value, "string"))?;
    Ok(super::parse_txid(text, label)?.0)
}

fn wait(
    ctx: &Context,
    condition: TipWaitCondition,
    deadline: Option<Instant>,
    cancellation: &LatchReader,
) -> Result<Value, RpcError> {
    let owner = ctx
        .chain
        .active_tip_wait
        .as_ref()
        .ok_or_else(|| RpcError::Misc("Active tip wait is unavailable".to_owned()))?;
    let tip = owner
        .wait_for_tip(condition, deadline, cancellation)
        .ok_or_else(|| RpcError::Misc("Active tip is not initialized".to_owned()))?;
    Ok(json!({"hash": tip.hash.to_string(), "height": tip.height}))
}

pub(crate) fn waitfornewblock(
    ctx: &Arc<Context>,
    params: &Value,
    cancellation: &LatchReader,
) -> Result<Value, RpcError> {
    let params = arguments(
        params,
        &["timeout", "current_tip"],
        0,
        "waitfornewblock ( timeout \"current_tip\" )",
    )?;
    let deadline = timeout(params.get(0), 1)?;
    let current = params
        .get(1)
        .filter(|value| !value.is_null())
        .map(|value| hash(value, 2, "current_tip"))
        .transpose()?;
    wait(
        ctx,
        TipWaitCondition::Changed(current),
        deadline,
        cancellation,
    )
}

pub(crate) fn waitforblock(
    ctx: &Arc<Context>,
    params: &Value,
    cancellation: &LatchReader,
) -> Result<Value, RpcError> {
    let params = arguments(
        params,
        &["blockhash", "timeout"],
        1,
        "waitforblock \"blockhash\" ( timeout )",
    )?;
    let absent = Value::new_null();
    let target = hash(params.get(0).unwrap_or(&absent), 1, "blockhash")?;
    let deadline = timeout(params.get(1), 2)?;
    wait(ctx, TipWaitCondition::Hash(target), deadline, cancellation)
}

pub(crate) fn waitforblockheight(
    ctx: &Arc<Context>,
    params: &Value,
    cancellation: &LatchReader,
) -> Result<Value, RpcError> {
    let params = arguments(
        params,
        &["height", "timeout"],
        1,
        "waitforblockheight height ( timeout )",
    )?;
    let absent = Value::new_null();
    let height = integer(params.get(0).unwrap_or(&absent), 1, "height")?;
    let deadline = timeout(params.get(1), 2)?;
    wait(
        ctx,
        TipWaitCondition::Height(height),
        deadline,
        cancellation,
    )
}
