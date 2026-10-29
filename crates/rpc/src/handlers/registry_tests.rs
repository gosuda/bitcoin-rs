#![expect(clippy::expect_used)]

use alloc::collections::BTreeSet;
use alloc::sync::Arc;

use sonic_rs::{JsonValueTrait as _, json};

use super::{Handler, live_registry, optional_bool, parse_txid, required_str, required_u64};
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
    assert_eq!(
        error.to_string(),
        "Wrong type passed:\n{\n    \"Position 1 (height)\": \"JSON value of type string is not of expected type number\"\n}"
    );
}

#[test]
#[expect(clippy::expect_used)]
fn missing_required_parameter_keeps_the_shape_error() {
    let params = json!([]);
    let error = required_str(&params, 0, "txid is required").expect_err("missing");
    assert_eq!(error.code(), RpcError::INVALID_PARAMS);
    assert_eq!(error.to_string(), "invalid params: txid is required");
}

#[test]
#[expect(clippy::expect_used)]
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
#[expect(clippy::expect_used)]
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
        format!(
            "parameter 1 must be hexadecimal string (not '{}')",
            "z".repeat(64)
        )
    );
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
    assert_eq!(
        error.to_string(),
        "Parameter inputs specified twice both as positional and named argument"
    );
    let error = handler
        .dispatch(
            "decoderawtransaction",
            &json!({"hexstring": "02000000000000000000", "extra": 1}),
        )
        .expect_err("unknown name");
    assert_eq!(error.code(), -8);
    assert_eq!(error.to_string(), "Unknown named parameter extra");
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
        assert_eq!(error.to_string(), "invalid params: too many parameters");
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

fn test_context() -> (Arc<Context>, Arc<bitcoin_rs_chainstate::Chainstate>) {
    let chainstate = Arc::new(bitcoin_rs_chainstate::Chainstate::new(
        bitcoin_rs_primitives::Network::Regtest,
        Arc::new(arc_swap::ArcSwapOption::empty()),
        Arc::new(arc_swap::ArcSwapOption::empty()),
        Arc::new(parking_lot::RwLock::new(bitcoin_rs_chain::BlockTree::new())),
        Arc::new(bitcoin_rs_utxo::UtxoSet::new()),
        Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::default(),
        )),
        Arc::new(bitcoin_rs_chainstate::events::ChainEventPublisher::detached(0)),
    ));
    chainstate
        .apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
            bitcoin_rs_primitives::Network::Regtest.genesis_block(),
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
