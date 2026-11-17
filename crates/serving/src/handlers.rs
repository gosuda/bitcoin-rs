use alloc::borrow::Cow;
use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin_rs_consensus::primitives::Txid;
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
    stop: bitcoin_rs_consensus::latch::LatchWriter,
    blocking_requests: parking_lot::Mutex<(usize, usize)>,
}

impl Handler {
    #[must_use]
    pub fn new(ctx: Arc<Context>) -> Self {
        Self {
            ctx,
            stop: bitcoin_rs_consensus::latch::LatchWriter::new(),
            blocking_requests: parking_lot::Mutex::new((0, 16)),
        }
    }

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
        self.stop.reader().is_triggered()
    }

    pub(crate) fn stop(&self) {
        self.stop.trigger();
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
        let bound = row
            .arg_names
            .map(|names| bind_named_params(params, names))
            .transpose()?;
        let params = bound.as_ref().map_or(params, |bound| bound.as_ref());
        let _blocking = row
            .execution
            .is_blocking(params)
            .then(|| {
                self.reserve_blocking_request().map_err(|error| {
                    if matches!(row.execution, crate::registry::Execution::Scan)
                        && self.ctx.chain.utxo.scan_progress().is_some()
                    {
                        RpcError::ScanInProgress(
                            bitcoin_rs_storage::utxo::scan::UtxoScanError::InProgress.to_string(),
                        )
                    } else {
                        error
                    }
                })
            })
            .transpose()?;
        let _active = self.ctx.active_calls.begin(method);
        let cancellation = self.stop.reader();
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
    if params.is_null() {
        return Ok(default);
    }
    let array = params_array(params)?;
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
    let value = params_array(params)?
        .get(index)
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
mod registry_tests {
    #![expect(clippy::expect_used)]

    use alloc::collections::BTreeSet;
    use alloc::sync::Arc;

    use sonic_rs::{JsonValueTrait as _, json};

    use super::{Handler, live_registry, optional_bool, parse_txid, required_str, required_u64};
    use crate::context::Context;
    use crate::error::RpcError;
    use crate::manifest::{self, SurfaceKind};

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
                    Err(RpcError::MethodNotFound(name)) if name != entry.name,
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

    #[test]
    fn pool_extensions_follow_compile_and_runtime_gates() {
        let handler = Handler::new(Arc::new(Context::new()));
        for method in [
            "registerpoolaccount",
            "preparepayoutbatch",
            "getpayoutrequest",
            "recordpayoutreceipt",
            "getpayoutbatch",
            "cancelpayoutbatch",
            "getpoolinfo",
            "getpoolrounds",
            "getpoolbalances",
        ] {
            let result = handler.dispatch(method, &json!([]));
            #[cfg(feature = "pool")]
            assert!(matches!(result, Err(RpcError::MethodDisabled(_))));
            #[cfg(not(feature = "pool"))]
            assert!(matches!(result, Err(RpcError::MethodNotFound(_))));
        }
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn wrong_json_type_answers_core_type_error_text() {
        let params = json!(["abc"]);
        let error = required_u64(&params, 0, "height is required").expect_err("type error");
        assert_eq!(error.code(), RpcError::CORE_INVALID_TYPE);
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn missing_required_parameter_keeps_the_shape_error() {
        let params = json!([]);
        let error = required_str(&params, 0, "txid is required").expect_err("missing");
        assert_eq!(error.code(), RpcError::INVALID_PARAMS);
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn optional_boolean_type_error_names_the_type() {
        let params = json!(["ignored", "yes"]);
        let error = optional_bool(&params, 1, true).expect_err("type error");
        assert_eq!(error.code(), RpcError::CORE_INVALID_TYPE);
    }
    #[test]
    #[expect(clippy::expect_used)]
    fn rejects_non_array_params_for_optional_bool() {
        let bad_params = json!("not an array");
        let error = optional_bool(&bad_params, 0, true).expect_err("must reject non-array");
        assert_eq!(error.code(), RpcError::INVALID_PARAMS);

        let object_params = json!({"flag": true});
        let error = optional_bool(&object_params, 0, true).expect_err("must reject non-array");
        assert_eq!(error.code(), RpcError::INVALID_PARAMS);
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn rejects_non_array_params_for_required_i64() {
        let bad_params = json!("not an array");
        let error = super::required_i64(&bad_params, 0, "height is required")
            .expect_err("must reject non-array");
        assert_eq!(error.code(), RpcError::INVALID_PARAMS);
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn txid_parameter_errors_use_core_text() {
        let short = parse_txid("123", "parameter 1").expect_err("short");
        assert_eq!(short.code(), RpcError::CORE_INVALID_PARAMETER);
        let non_hex = parse_txid(&"z".repeat(64), "parameter 1").expect_err("non-hex");
        assert_eq!(non_hex.code(), RpcError::CORE_INVALID_PARAMETER);
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn named_transaction_arguments_follow_core() {
        let handler = Handler::new(Arc::new(Context::new()));
        for params in [
            json!({"inputs": [], "outputs": {}, "locktime": 7}),
            json!({"args": [[]], "outputs": {}, "locktime": 7}),
            json!({"args": false, "inputs": [], "outputs": {}, "locktime": 7}),
        ] {
            assert_eq!(
                handler
                    .dispatch("createrawtransaction", &params)
                    .expect("named create"),
                json!("02000000000007000000")
            );
        }
        let error = handler
            .dispatch(
                "createrawtransaction",
                &json!({"args": [[], {}], "inputs": null, "extra": 1}),
            )
            .expect_err("named null still conflicts before unknown-name rejection");
        assert_eq!(error.code(), -8);
        let error = handler
            .dispatch(
                "decoderawtransaction",
                &json!({"hexstring": "02000000000000000000", "extra": 1}),
            )
            .expect_err("unknown name");
        assert_eq!(error.code(), -8);
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn unsupported_creation_version_is_never_silently_ignored() {
        let handler = Handler::new(Arc::new(Context::new()));
        for params in [
            json!([[], {}, 0, false, 1]),
            json!({"args": [[], {}, 0, false, 1]}),
            json!([[], {}, 0, false, null]),
            json!({"args": [[], {}, 0, false, null]}),
            json!([[], {}, 0, false, 1, null]),
            json!({"args": [[], {}, 0, false, 1, null]}),
        ] {
            let error = handler
                .dispatch("createrawtransaction", &params)
                .expect_err("unsupported fifth argument must not produce version 2");
            assert_eq!(error.code(), -32602);
        }
        assert_eq!(
            handler
                .dispatch("createrawtransaction", &json!([[], {}, 0, false]))
                .expect("supported four-argument creation"),
            json!("02000000000000000000")
        );
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn named_binding_preserves_method_boundaries() {
        let handler = Handler::new(Arc::new(Context::new()));
        for params in [
            json!({"options": {}}),
            json!({"options": null}),
            json!({"mempool_only": true}),
            json!({"return_spending_tx": false, "args": []}),
            json!({"mempool_only": true, "args": false}),
        ] {
            let error = handler
                .dispatch("gettxspendingprevout", &params)
                .expect_err("outputs omitted");
            assert_eq!(error.code(), -32602);
            assert_eq!(error.to_string(), "invalid params: outputs is required");
        }
        for params in [
            json!({"outputs": null, "mempool_only": true}),
            json!({"args": [null], "return_spending_tx": false}),
        ] {
            assert_eq!(
                handler
                    .dispatch("gettxspendingprevout", &params)
                    .expect_err("explicit null is a type error")
                    .code(),
                -3
            );
        }
        let error = handler
            .dispatch("gettxspendingprevout", &json!({"options": {}, "extra": 0}))
            .expect_err("name validation precedes missing outputs");
        assert_eq!(error.code(), -8);
        assert_eq!(error.to_string(), "Unknown named parameter extra");
        for (method, params, name) in [
            (
                "createrawtransaction",
                json!({"inputs": [], "outputs": {}, "version": 1}),
                "version",
            ),
            (
                "decoderawtransaction",
                json!({"hexstring": "zz", "iswitness": false}),
                "iswitness",
            ),
        ] {
            let error = handler
                .dispatch(method, &params)
                .expect_err("unsupported name");
            assert_eq!(error.code(), -8);
            assert_eq!(error.to_string(), format!("Unknown named parameter {name}"));
        }
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn named_parameters_match_positional_arguments_for_core_methods() {
        let handler = Handler::new(Arc::new(Context::new()));
        let txid = "00".repeat(32);
        let hash = "11".repeat(32);
        let observed = |result: Result<sonic_rs::Value, RpcError>| {
            result.map_err(|error| (error.code(), error.to_string()))
        };
        for (method, named, positional) in [
            ("getblockhash", json!({"height": 0}), json!([0])),
            (
                "getblockheader",
                json!({"blockhash": hash.as_str(), "verbose": false}),
                json!([hash.as_str(), false]),
            ),
            (
                "gettxoutsetinfo",
                json!({"hash_type": "none"}),
                json!(["none"]),
            ),
            (
                "gettxoutsetinfo",
                json!({"hash_or_height": 0}),
                json!([null, 0]),
            ),
            ("getrawmempool", json!({"verbose": true}), json!([true])),
            (
                "getrawmempool",
                json!({"mempool_sequence": true}),
                json!([null, true]),
            ),
            (
                "getmempoolancestors",
                json!({"txid": txid.as_str(), "verbose": false}),
                json!([txid.as_str(), false]),
            ),
            (
                "getmempooldescendants",
                json!({"txid": txid.as_str(), "verbose": false}),
                json!([txid.as_str(), false]),
            ),
            (
                "generatetoaddress",
                json!({"nblocks": 1, "address": "regtest"}),
                json!([1, "regtest"]),
            ),
            (
                "generateblock",
                json!({"output": "regtest", "transactions": []}),
                json!(["regtest", []]),
            ),
            (
                "setban",
                json!({"subnet": "127.0.0.1", "command": "add"}),
                json!(["127.0.0.1", "add"]),
            ),
            (
                "getnodeaddresses",
                json!({"count": 5, "network": "ipv4"}),
                json!([5, "ipv4"]),
            ),
            (
                "gettxout",
                json!({"txid": txid.as_str(), "n": 0}),
                json!([txid.as_str(), 0]),
            ),
            ("finalizepsbt", json!({"psbt": "zz"}), json!(["zz"])),
            (
                "estimatesmartfee",
                json!({"conf_target": 6, "estimate_mode": "conservative"}),
                json!([6, "conservative"]),
            ),
        ] {
            assert_eq!(
                observed(handler.dispatch(method, &named)),
                observed(handler.dispatch(method, &positional)),
                "{method} named parameters must bind like positional parameters"
            );
        }
        assert_eq!(
            observed(handler.dispatch("getrawmempool", &json!({"mempool_sequence": true}))),
            Ok(json!({"txids": [], "mempool_sequence": 0}))
        );
        let error = handler
            .dispatch("gettxoutsetinfo", &json!({"hash_or_height": 0}))
            .expect_err("named hash_or_height requires the coinstats index");
        assert_eq!(
            error.to_string(),
            "Querying specific block heights requires coinstatsindex"
        );
        let error = handler
            .dispatch(
                "estimatesmartfee",
                &json!({"conf_target": 6, "estimate_mode": "bogus"}),
            )
            .expect_err("named mode");
        assert_eq!(error.code(), RpcError::CORE_INVALID_PARAMETER);
    }

    #[test]
    #[expect(clippy::expect_used)]
    fn named_parameter_errors_use_core_invalid_parameter_code() {
        let handler = Handler::new(Arc::new(Context::new()));
        let error = handler
            .dispatch("getblockhash", &json!({"height": 0, "extra": 1}))
            .expect_err("unknown name");
        assert_eq!(error.code(), -8);
        assert_eq!(error.to_string(), "Unknown named parameter extra");
        let error = handler
            .dispatch(
                "getblockheader",
                &json!({"args": ["00"], "blockhash": "00"}),
            )
            .expect_err("positional and named conflict");
        assert_eq!(error.code(), -8);
        assert_eq!(
            error.to_string(),
            "Parameter blockhash specified twice both as positional and named argument"
        );
    }

    fn test_context() -> (Arc<Context>, Arc<bitcoin_rs_execution::Chainstate>) {
        let chainstate = Arc::new(bitcoin_rs_execution::Chainstate::new(
            bitcoin_rs_consensus::primitives::Network::Regtest,
            Arc::new(arc_swap::ArcSwapOption::empty()),
            Arc::new(arc_swap::ArcSwapOption::empty()),
            Arc::new(parking_lot::RwLock::new(
                bitcoin_rs_execution::chain::BlockTree::new(),
            )),
            Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
            Arc::new(bitcoin_rs_storage::utxo::stats::CoinStatsListener::new(
                bitcoin_rs_storage::utxo::stats::CoinStats::default(),
            )),
            Arc::new(bitcoin_rs_execution::events::ChainEventPublisher::detached(
                0,
            )),
        ));
        chainstate
            .apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                bitcoin_rs_consensus::primitives::Network::Regtest.genesis_block(),
            ))
            .expect("genesis");
        let mut ctx = Context::new();
        ctx.chain.applied_tip = chainstate.applied_tip_reader();
        ctx.chain.active_tip_wait = Some(chainstate.clone());
        (Arc::new(ctx), chainstate)
    }

    fn await_waiter(handler: &Handler) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            let active = handler.blocking_requests.lock().0;
            if active != 0 {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "request must enter the bounded wait quota"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    #[test]
    fn one_worker_rejects_waits_and_direct_dispatch_cannot_bypass_budget() {
        let (ctx, _) = test_context();
        let handler = Arc::new(Handler::new(Arc::clone(&ctx)));
        handler.configure_blocking_admission(1);
        assert!(
            handler
                .dispatch("waitforblockheight", &json!([-1]))
                .is_err()
        );
        assert_eq!(
            handler
                .dispatch("getblockcount", &json!([]))
                .expect("ordinary")
                .as_u64(),
            Some(0)
        );
        handler.configure_blocking_admission(2);
        let waiter = Arc::clone(&handler);
        let task = std::thread::spawn(move || waiter.dispatch("waitforblockheight", &json!([1])));
        await_waiter(&handler);
        assert!(handler.dispatch("waitfornewblock", &json!([1])).is_err());
        assert_eq!(
            handler
                .dispatch("getblockcount", &json!([]))
                .expect("ordinary")
                .as_u64(),
            Some(0)
        );
        handler.stop();
        assert_eq!(
            task.join().expect("waiter").expect("cancel returns tip")["height"].as_u64(),
            Some(0)
        );
    }
}
