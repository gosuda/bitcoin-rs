#![expect(clippy::expect_used, reason = "test assertions")]

use std::sync::{Arc, Barrier, mpsc};
use std::time::Duration;

use sonic_rs::json;

use super::*;
use crate::{Handler, context::Context};

#[test]
fn byte_and_worker_reservations_are_shared_and_released() {
    let budget = Arc::new(Admission::default());
    let full = "00".repeat(MAX_WIRE_BYTES);
    let permit = budget
        .reserve([full.as_str()])
        .expect("one full inspection");
    assert!(budget.reserve(["00"]).is_err());
    drop(permit);

    let barrier = Arc::new(Barrier::new(MAX_ACTIVE + 1));
    let (tx, rx) = mpsc::channel();
    let workers = (0..MAX_ACTIVE)
        .map(|_| {
            let budget = Arc::clone(&budget);
            let barrier = Arc::clone(&barrier);
            let tx = tx.clone();
            std::thread::spawn(move || {
                let _permit = budget.reserve(["00"]).expect("reserved worker");
                tx.send(()).expect("admitted");
                barrier.wait();
            })
        })
        .collect::<Vec<_>>();
    for _ in 0..MAX_ACTIVE {
        rx.recv_timeout(Duration::from_secs(5))
            .expect("worker ready");
    }
    let refused = budget.reserve(["00"]).is_err();
    barrier.wait();
    for worker in workers {
        worker.join().expect("worker exit");
    }
    assert!(refused);
    assert!(budget.reserve([full.as_str()]).is_ok());
}

#[test]
fn rpc_and_public_broadcast_refuse_before_decode_without_taking_blocking_slots() {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));
    handler.configure_blocking_admission(1);
    let full = "00".repeat(MAX_WIRE_BYTES);
    let permit = ctx
        .tx_decode_admission
        .reserve([full.as_str()])
        .expect("reserve bytes");
    for (method, params) in [
        ("sendrawtransaction", json!(["not hex"])),
        ("decoderawtransaction", json!({"hexstring":"not hex"})),
        ("testmempoolaccept", json!([["not hex"]])),
        ("submitpackage", json!([["not hex"]])),
    ] {
        let error = handler.dispatch(method, &params).expect_err("overload");
        assert_eq!(error.code(), -1);
        assert_eq!(error.to_string(), BUSY);
    }
    for surface in [
        crate::esplora::Surface::Public,
        crate::esplora::Surface::Backend,
    ] {
        let response = crate::esplora::route_post(&handler, surface, "/tx", b"not hex");
        assert_eq!(response.status, 503);
        let oversize = "00".repeat(400_001);
        assert_eq!(
            crate::esplora::route_post(&handler, surface, "/tx", oversize.as_bytes()).status,
            400
        );
    }
    assert!(handler.dispatch("getblockcount", &json!([])).is_ok());
    drop(permit);
    assert_eq!(
        handler
            .dispatch("decoderawtransaction", &json!(["not hex"]))
            .expect_err("decode")
            .code(),
        RpcError::CORE_DESERIALIZATION_ERROR
    );
    // Both failure paths returned their reservation.
    assert_eq!(*ctx.tx_decode_admission.used.lock(), (0, 0));
}

#[test]
fn oversized_hex_and_package_do_not_consume_a_reservation() {
    let budget = Admission::default();
    let at_limit = "00".repeat(MAX_WIRE_BYTES);
    assert!(budget.reserve([at_limit.as_str()]).is_ok());
    assert_eq!(
        budget
            .reserve([at_limit.as_str(), "00"])
            .err()
            .expect("aggregate bound")
            .code(),
        RpcError::CORE_DESERIALIZATION_ERROR
    );
    let over_limit = at_limit + "00";
    assert_eq!(
        budget
            .reserve([over_limit.as_str()])
            .err()
            .expect("single bound")
            .code(),
        RpcError::CORE_DESERIALIZATION_ERROR
    );
    assert_eq!(*budget.used.lock(), (0, 0));
}
