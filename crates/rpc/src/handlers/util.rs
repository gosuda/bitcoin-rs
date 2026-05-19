use alloc::sync::Arc;

use sonic_rs::{Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::required_u64;

pub(crate) fn estimatesmartfee(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    required_u64(params, 0, "conf_target is required")?;
    Ok(json!({
        "feerate": 0.0,
        "blocks": 0
    }))
}

pub(crate) fn estimaterawfee(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    required_u64(params, 0, "conf_target is required")?;
    Ok(json!({
        "short": {"feerate": 0.0, "decay": 0.0, "scale": 0},
        "medium": {"feerate": 0.0, "decay": 0.0, "scale": 0},
        "long": {"feerate": 0.0, "decay": 0.0, "scale": 0}
    }))
}
