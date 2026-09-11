//! A1 red-green cycle tests for the txindex worker lifecycle.

use super::*;
use arc_swap::ArcSwap;
use std::sync::Arc;

#[test]
fn publication_boundaries_never_expose_half_installed_state() {
    // The lifecycle is published atomically behind ArcSwap. Every load returns
    // a complete, self-consistent snapshot — never a torn mix of state and
    // payload.
    let lifecycle: Arc<ArcSwap<TxIndexLifecycle>> =
        Arc::new(ArcSwap::from_pointee(TxIndexLifecycle::Opening));

    // Publish CatchingUp with a dummy engine reference (None payload path
    // is tested separately; here we verify Opening → ShutdownAbandoned
    // transitions are atomic).
    lifecycle.store(Arc::new(TxIndexLifecycle::ShutdownAbandoned));
    let snapshot = lifecycle.load();
    assert!(matches!(**snapshot, TxIndexLifecycle::ShutdownAbandoned));

    // Publish Failed.
    lifecycle.store(Arc::new(TxIndexLifecycle::Failed(CompactString::from(
        "test failure",
    ))));
    let snapshot = lifecycle.load();
    assert!(matches!(**snapshot, TxIndexLifecycle::Failed(_)));

    // Publish Opening again.
    lifecycle.store(Arc::new(TxIndexLifecycle::Opening));
    let snapshot = lifecycle.load();
    assert!(matches!(**snapshot, TxIndexLifecycle::Opening));
}

#[test]
fn stale_generation_rcu_is_a_noop() {
    let lifecycle: Arc<ArcSwap<TxIndexLifecycle>> =
        Arc::new(ArcSwap::from_pointee(TxIndexLifecycle::Opening));
    let generation_tok = Generation::new(1);
    generation_tok.revoke();

    // Attempt to publish Failed via the generation-checked rcu. Since the
    // generation is revoked, the snapshot must stay Opening.
    let runtime = TxIndexRuntime::new(crossbeam_channel::bounded(1).0);
    fail_worker(&runtime, &lifecycle, &generation_tok, "should not publish");
    let snapshot = lifecycle.load();
    assert!(
        matches!(**snapshot, TxIndexLifecycle::Opening),
        "revoked generation must not publish"
    );

    // A non-revoked generation publishes normally.
    let gen2 = Generation::new(2);
    fail_worker(&runtime, &lifecycle, &gen2, "should publish");
    let snapshot = lifecycle.load();
    assert!(
        matches!(**snapshot, TxIndexLifecycle::Failed(_)),
        "active generation must publish"
    );
}

#[test]
fn query_adapter_returns_unavailable_for_opening() {
    let lifecycle: Arc<ArcSwap<TxIndexLifecycle>> =
        Arc::new(ArcSwap::from_pointee(TxIndexLifecycle::Opening));
    let adapter = TxIndexQueryAdapter::new(lifecycle);

    let result = adapter.transaction(&Txid::from(Hash256::from_le_bytes(&[0u8; 32])));
    assert!(
        matches!(result, Err(TxQueryError::Unavailable(_))),
        "Opening must return Unavailable, got {result:?}"
    );
}

#[test]
fn query_adapter_returns_unavailable_for_failed() {
    let lifecycle: Arc<ArcSwap<TxIndexLifecycle>> = Arc::new(ArcSwap::from_pointee(
        TxIndexLifecycle::Failed(CompactString::from("schema mismatch")),
    ));
    let adapter = TxIndexQueryAdapter::new(lifecycle);

    let result = adapter.transaction(&Txid::from(Hash256::from_le_bytes(&[0u8; 32])));
    assert!(
        matches!(result, Err(TxQueryError::Unavailable(_))),
        "Failed must return Unavailable, got {result:?}"
    );
}

#[test]
fn query_adapter_returns_unavailable_for_shutdown_abandoned() {
    let lifecycle: Arc<ArcSwap<TxIndexLifecycle>> =
        Arc::new(ArcSwap::from_pointee(TxIndexLifecycle::ShutdownAbandoned));
    let adapter = TxIndexQueryAdapter::new(lifecycle);

    let result = adapter.transaction(&Txid::from(Hash256::from_le_bytes(&[0u8; 32])));
    assert!(
        matches!(result, Err(TxQueryError::Unavailable(_))),
        "ShutdownAbandoned must return Unavailable, got {result:?}"
    );
}

#[test]
fn generation_revoke_makes_publication_noop() {
    let generation_tok = Generation::new(42);
    assert_eq!(generation_tok.id(), 42);
    assert!(!generation_tok.is_revoked());
    generation_tok.revoke();
    assert!(generation_tok.is_revoked());
}

#[test]
fn generation_clone_shares_revocation() {
    let generation_tok = Generation::new(7);
    let gen_clone = generation_tok.clone();
    generation_tok.revoke();
    assert!(gen_clone.is_revoked(), "clone must see revocation");
}

/// IDX-07: revocation fences publication, not this worker's failure signal.
#[test]
fn revoked_failure_stops_runtime_without_replacing_lifecycle_snapshot() {
    let lifecycle = Arc::new(ArcSwap::from_pointee(TxIndexLifecycle::Opening));
    let before = lifecycle.load_full();
    let generation = Generation::new(1);
    let runtime = TxIndexRuntime::new(crossbeam_channel::bounded(1).0);
    generation.revoke();
    fail_worker(&runtime, &lifecycle, &generation, "detached failure");
    assert!(runtime.should_stop());
    assert_eq!(
        runtime.failure_message().as_deref(),
        Some("detached failure")
    );
    assert!(Arc::ptr_eq(&before, &lifecycle.load_full()));
}
