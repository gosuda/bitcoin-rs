//! Focused coverage for watch-only wallet RPC methods.
extern crate alloc;

use alloc::sync::Arc;

use bitcoin_rs_rpc::context::Context;
use bitcoin_rs_rpc::{Handler, RpcError};
use bitcoin_rs_wallet::Watcher;
use parking_lot::RwLock;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

fn handler_with_wallet() -> Handler {
    let ctx = Context::new().with_wallet(Arc::new(RwLock::new(Watcher::new(Vec::new()))));
    Handler::new(Arc::new(ctx))
}

#[test]
fn registered_descriptor_methods_accept_addr_descriptors() -> Result<(), Box<dyn std::error::Error>>
{
    let handler = Handler::new(Arc::new(Context::new()));
    let info = handler.dispatch(
        "getdescriptorinfo",
        &json!(["addr(1111111111111111111114oLvT2)"]),
    )?;
    assert_eq!(
        info.get("hasprivatekeys").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(
        info.get("checksum").and_then(|v| v.as_str()).map(str::len),
        Some(8)
    );

    let derived = handler.dispatch(
        "deriveaddresses",
        &json!(["addr(1111111111111111111114oLvT2)"]),
    )?;
    assert_eq!(derived.as_array().map(|arr| arr.len()), Some(1));
    Ok(())
}

#[test]
fn registered_descriptor_checksum_failure_is_invalid_params() {
    let handler = Handler::new(Arc::new(Context::new()));
    let err = handler
        .dispatch(
            "getdescriptorinfo",
            &json!(["addr(1111111111111111111114oLvT2)#00000000"]),
        )
        .expect_err("bad checksum");
    assert!(matches!(
        err,
        RpcError::InvalidParams(_) | RpcError::InvalidParameter(_)
    ));
}

#[test]
fn custody_methods_are_not_registered_as_custom_handlers() {
    // I1 removes the temporary method_disabled arms so these resolve as
    // generic method-not-found. Accept either shape until that lands.
    let handler = handler_with_wallet();
    for method in [
        "dumpprivkey",
        "importprivkey",
        "dumpwallet",
        "importwallet",
        "walletpassphrase",
        "encryptwallet",
        "signrawtransactionwithwallet",
    ] {
        let err = handler.dispatch(method, &json!([])).expect_err(method);
        assert!(
            matches!(
                err,
                RpcError::MethodNotFound(_) | RpcError::MethodDisabled(_)
            ),
            "{method} returned {err:?}"
        );
        if let RpcError::MethodDisabled(message) = err {
            assert!(
                !message.contains("not implemented"),
                "no bespoke custody implementation leak"
            );
        }
    }
}

#[test]
fn walletcreatefundedpsbt_and_process_round_trip_empty_psbt()
-> Result<(), Box<dyn std::error::Error>> {
    let handler = Handler::new(Arc::new(Context::new()));
    let created = handler.dispatch("walletcreatefundedpsbt", &json!([[], []]))?;
    assert!(created.get("psbt").and_then(|v| v.as_str()).is_some());
    assert_eq!(created.get("changepos").and_then(|v| v.as_i64()), Some(-1));

    let psbt = created
        .get("psbt")
        .and_then(|v| v.as_str())
        .ok_or("missing psbt")?;
    let processed = handler.dispatch("walletprocesspsbt", &json!([psbt]))?;
    assert_eq!(
        processed.get("complete").and_then(|v| v.as_bool()),
        Some(false)
    );
    Ok(())
}
