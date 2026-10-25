//! `verifychain` parameter boundaries and pre-delegation outcomes.
//!
//! The handler validates Core's signed parameters, honors handler shutdown,
//! and answers a tip without a verifier as unverified. The node-owned
//! verifier's answers, including the applied-genesis window, are proven
//! against the real verifier in `node` (`lifecycle` tests) and in
//! `chainstate::verify`; the stub control below proves delegation to the
//! attached control, not its answers.
#![expect(clippy::unwrap_used)]

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use super::*;
use crate::context::{ChainControl, ChainControlError};
use crate::handlers::Handler;

/// A context whose applied tip is genesis, with no chain control attached.
fn tipped() -> Arc<Context> {
    Arc::new(tipped_context())
}

fn tipped_context() -> Context {
    let ctx = Context::new();
    let genesis = Network::Regtest.genesis_block();
    ctx.chain
        .block_tree
        .write()
        .insert_node(None, genesis.header, NodeStatus::Active)
        .unwrap();
    ctx.chain
        .applied_tip
        .store(ctx.chain.block_tree.read().tip());
    assert!(
        ctx.chain.applied_tip.load_full().is_some(),
        "the fixture must apply its tip"
    );
    ctx
}

#[test]
fn parameters_follow_core_signed_ranges() {
    let handler = Handler::new(Arc::new(Context::new()));
    // No applied tip: nothing to verify, whatever the window.
    for params in [
        json!([]),
        json!([3, 6]),
        json!([0, 6]),
        json!([4, 0]),
        json!([-1, -1]),
        json!([null, null]),
        json!([5, 0]),
        json!([3, 2_147_483_647]),
    ] {
        let result = handler
            .dispatch("verifychain", &params)
            .unwrap_or_else(|err| panic!("verifychain{params:?} failed: {err}"));
        assert_eq!(result.as_bool(), Some(true), "{params:?}");
    }

    // Core reads both parameters with `getInt`: a non-number is a type
    // error, anything outside the signed 32-bit range is out of range.
    for params in [json!(["0"]), json!([0, false])] {
        assert_eq!(
            handler.dispatch("verifychain", &params).unwrap_err().code(),
            -3,
            "{params:?}"
        );
    }
    for params in [
        json!([2_147_483_648_i64]),
        json!([3, 2_147_483_648_i64]),
        json!([9, i64::MIN]),
        json!([0, -2_147_483_649_i64]),
        json!([0, 0.5]),
        json!([3, u64::from(u32::MAX) + 1]),
        json!([3, u64::MAX]),
    ] {
        assert_eq!(
            handler.dispatch("verifychain", &params).unwrap_err().code(),
            -1,
            "{params:?}"
        );
    }
    assert_eq!(
        handler
            .dispatch("verifychain", &json!([0, 0, 0]))
            .unwrap_err()
            .code(),
        -32602
    );
}

#[test]
fn cancelled_requests_report_interruption() {
    let handler = Handler::new(tipped());
    // The same request over the same applied tip answers `false` while the
    // handler runs (no verifier attached), so the error below is the
    // handler's own pre-dispatch interruption, not a verifier outcome.
    assert_eq!(
        handler.dispatch("verifychain", &json!([0, 0])).unwrap(),
        json!(false)
    );
    handler.stop();
    let error = handler.dispatch("verifychain", &json!([0, 0])).unwrap_err();
    assert_eq!(error.code(), -1);
    assert_eq!(error.to_string(), "Block verification interrupted");
}

#[test]
fn tip_without_control_is_not_verified() {
    let handler = Handler::new(tipped());
    for level in 0..=4 {
        assert_eq!(
            handler.dispatch("verifychain", &json!([level, 6])).unwrap(),
            json!(false),
            "level {level} without a verifier"
        );
    }
}

struct StubControl {
    calls: AtomicBool,
    level: AtomicU8,
    nblocks: AtomicU32,
}

impl ChainControl for StubControl {
    fn invalidate_block(
        &self,
        _hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<(), ChainControlError> {
        Err(ChainControlError::UnknownBlock)
    }

    fn dump_txoutset(
        &self,
        _path: &std::path::Path,
        _cancellation: &bitcoin_rs_chain::LatchReader,
    ) -> Result<crate::context::SnapshotExport, crate::context::SnapshotControlError> {
        Err(crate::context::SnapshotControlError::Unavailable(
            "snapshot export is not attached to this stub".to_owned(),
        ))
    }

    fn verify_chain(
        &self,
        check_level: u8,
        nblocks: u32,
        _cancellation: &bitcoin_rs_chain::LatchReader,
    ) -> Result<bool, ChainControlError> {
        self.calls.store(true, Ordering::SeqCst);
        self.level.store(check_level, Ordering::SeqCst);
        self.nblocks.store(nblocks, Ordering::SeqCst);
        Ok(true)
    }
}

#[test]
fn empty_window_through_attached_control_is_verified() {
    let control = Arc::new(StubControl {
        calls: AtomicBool::new(false),
        level: AtomicU8::new(u8::MAX),
        nblocks: AtomicU32::new(u32::MAX),
    });
    let handler = Handler::new(Arc::new(
        tipped_context().with_chain_control(control.clone()),
    ));
    assert_eq!(
        handler.dispatch("verifychain", &json!([0, 0])).unwrap(),
        json!(true)
    );
    assert!(
        control.calls.load(Ordering::SeqCst),
        "the applied tip must consult the attached control, not the no-tip shortcut"
    );
    assert_eq!(control.level.load(Ordering::SeqCst), 0);
    assert_eq!(control.nblocks.load(Ordering::SeqCst), 0);
}
