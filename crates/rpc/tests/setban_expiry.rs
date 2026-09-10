//! Finite setban expiry and rejection without state mutation.
//!
//! Contract: SETBAN-EXPIRY-01 on `ban_until` in
//! `crates/rpc/src/handlers/network.rs`. The permanent-ban sentinel is owned
//! by `BannedSubnet` in `crates/p2p/src/subnet.rs`, not by timestamp arithmetic.
//! The default of 24 hours is independently specified by Bitcoin Core v31.1
//! `src/rpc/net.cpp::setban` and `src/banman.h::DEFAULT_MISBEHAVING_BANTIME`.
//! Rust's `SystemTime::checked_add` defines the representability boundary;
//! these tests do not claim full Bitcoin Core setban compatibility.

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use bitcoin_rs_p2p::BannedSubnet;
use bitcoin_rs_rpc::{Handler, RpcError, context::Context};
use sonic_rs::{JsonValueTrait as _, json};

fn handler() -> Handler {
    Handler::new(Arc::new(Context::new()))
}

fn only_ban(handler: &Handler) -> BannedSubnet {
    let entries = handler.context().banned.read();
    let [entry] = entries.as_slice() else {
        panic!("expected exactly one ban entry");
    };
    entry.clone()
}

fn assert_overflow_fixture() {
    // u64::MAX exercises the parser's full accepted integer range. Prove
    // that this fixture exceeds the platform's SystemTime range, rather
    // than silently skipping the rejection contract on a different target.
    assert!(
        UNIX_EPOCH
            .checked_add(Duration::from_secs(u64::MAX))
            .is_none(),
        "the overflow fixture must be unrepresentable on this target"
    );
}

fn assert_invalid_expiry(handler: &Handler, target: &str, absolute: bool) {
    let Err(error) = handler.dispatch("setban", &json!([target, "add", u64::MAX, absolute])) else {
        panic!("unrepresentable expiry must not succeed");
    };
    assert!(matches!(&error, RpcError::InvalidParameter(_)));
    assert_eq!(error.code(), -8, "SETBAN-EXPIRY-01 invalid-value error");
}

#[test]
fn overflow_does_not_create_a_permanent_ban() {
    assert_overflow_fixture();
    for absolute in [false, true] {
        let handler = handler();
        assert_invalid_expiry(&handler, "192.0.2.1", absolute);
        assert!(handler.context().banned.read().is_empty());
    }
}

#[test]
fn overflow_preserves_existing_entries_and_order() -> Result<(), RpcError> {
    assert_overflow_fixture();
    for absolute in [false, true] {
        // Exercise both replacement of an existing target and insertion of
        // a new target. Compare full records, including reasons and times.
        for target in ["192.0.2.1", "203.0.113.99"] {
            let handler = handler();
            handler.dispatch("setban", &json!(["192.0.2.1", "add", 60]))?;
            handler.dispatch("setban", &json!(["198.51.100.0/24", "add", 120]))?;
            let before = handler.context().banned.read().clone();

            assert_invalid_expiry(&handler, target, absolute);

            assert_eq!(
                handler.context().banned.read().as_slice(),
                before.as_slice()
            );
        }
    }
    Ok(())
}

#[test]
fn relative_defaults_and_explicit_durations_remain_finite() -> Result<(), RpcError> {
    for (params, expected_seconds) in [
        (json!(["192.0.2.1", "add"]), 86_400),
        (json!(["192.0.2.1", "add", null]), 86_400),
        (json!(["192.0.2.1", "add", 0, false]), 86_400),
        (json!(["192.0.2.1", "add", 1, false]), 1),
        (json!(["192.0.2.1", "add", 60, false]), 60),
    ] {
        let handler = handler();
        assert!(handler.dispatch("setban", &params)?.is_null());
        let entry = only_ban(&handler);
        assert!(entry.banned_until.is_some());
        // Derive from the stored creation instant, not a second wall-clock
        // observation, so this assertion has no scheduling tolerance.
        assert_eq!(
            entry.banned_until,
            entry
                .ban_created
                .checked_add(Duration::from_secs(expected_seconds))
        );
    }
    Ok(())
}

#[test]
fn absolute_expiry_uses_epoch_not_creation_time() -> Result<(), RpcError> {
    // A fixed, representable epoch timestamp, not a timing threshold.
    let seconds = 2_000_000_000_u64;
    let handler = handler();
    assert!(
        handler
            .dispatch("setban", &json!(["192.0.2.1", "add", seconds, true]))?
            .is_null()
    );
    let entry = only_ban(&handler);
    assert!(entry.banned_until.is_some());
    assert_eq!(
        entry.banned_until,
        UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
    );
    Ok(())
}
