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

use crate::manifest::{self, SurfaceKind};

/// Registration consults the compatibility manifest so the declared surface
/// and the dispatched surface cannot disagree.
fn is_registered_method(method: &str) -> bool {
    manifest::is_registered(SurfaceKind::Rpc, method)
}

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
    pub fn dispatch(&self, method: &str, params: &Value) -> Result<Value, RpcError> {
        if !is_registered_method(method) {
            return Err(RpcError::MethodNotFound(method.to_owned()));
        }
        let Some(row) = crate::registry::REGISTRY
            .iter()
            .find(|row| row.entry.name == method)
        else {
            unreachable!("registered RPC method missing a registry row: {method}");
        };
        let Some(handler) = row.handler else {
            return Err(RpcError::MethodNotFound(method.to_owned()));
        };
        handler(&self.ctx, params)
    }
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
        .ok_or(RpcError::InvalidType("parameter must be boolean"))
}

pub(crate) fn required_str<'a>(
    params: &'a Value,
    index: usize,
    name: &'static str,
) -> Result<&'a str, RpcError> {
    params_array(params)?
        .get(index)
        .and_then(JsonValueTrait::as_str)
        .ok_or(RpcError::InvalidParams(name))
}

pub(crate) fn required_u64(
    params: &Value,
    index: usize,
    name: &'static str,
) -> Result<u64, RpcError> {
    params_array(params)?
        .get(index)
        .and_then(JsonValueTrait::as_u64)
        .ok_or(RpcError::InvalidParams(name))
}

/// Parses one 64-hex-character transaction id, rejecting anything else.
pub(crate) fn parse_txid(value: &str) -> Result<Txid, RpcError> {
    Txid::from_str(value).map_err(|_| RpcError::InvalidParams("txid must be 64 hex characters"))
}
#[cfg(test)]
mod registry_tests {
    use alloc::collections::BTreeSet;
    use alloc::sync::Arc;

    use sonic_rs::json;

    use super::{Handler, live_registry};
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
}
