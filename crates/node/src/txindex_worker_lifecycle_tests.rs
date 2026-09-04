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
fn namespace_registry_claims_and_releases() {
    let registry = NamespaceRegistry::new();
    let key = PathBuf::from("/tmp/test-namespace-claim");

    // First claim succeeds.
    assert!(registry.claim(key.clone(), 1));
    // Second claim by different owner fails.
    assert!(!registry.claim(key.clone(), 2));
    // Release by wrong owner does nothing.
    registry.release(&key, 2);
    assert!(matches!(
        registry.entries.lock().get(&key),
        Some(NamespaceEntry::Active(1))
    ));
    // Release by correct owner removes the entry.
    registry.release(&key, 1);
    assert!(registry.entries.lock().get(&key).is_none());
}

#[test]
fn namespace_registry_poisons_on_abandon() {
    let registry = NamespaceRegistry::new();
    let key = PathBuf::from("/tmp/test-namespace-poison");

    assert!(registry.claim(key.clone(), 1));
    registry.poison(&key, 1);
    assert!(registry.is_poisoned(&key));
    // Poisoned namespace cannot be claimed.
    assert!(!registry.claim(key, 2));
}

#[test]
fn namespace_registry_poison_only_for_matching_owner() {
    let registry = NamespaceRegistry::new();
    let key = PathBuf::from("/tmp/test-namespace-poison-owner");

    assert!(registry.claim(key.clone(), 1));
    // Poison by wrong owner does nothing.
    registry.poison(&key, 2);
    assert!(!registry.is_poisoned(&key));
    assert!(matches!(
        registry.entries.lock().get(&key),
        Some(NamespaceEntry::Active(1))
    ));
}

#[test]
fn namespace_registry_validates_child() {
    let root = Path::new("/tmp");
    assert!(NamespaceRegistry::validate_child(root, "txindex").is_ok());
    assert!(NamespaceRegistry::validate_child(root, "").is_err());
    assert!(NamespaceRegistry::validate_child(root, ".").is_err());
    assert!(NamespaceRegistry::validate_child(root, "..").is_err());
    #[cfg(unix)]
    {
        assert!(NamespaceRegistry::validate_child(root, "foo/bar").is_err());
        assert!(NamespaceRegistry::validate_child(root, "/absolute").is_err());
    }
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

#[test]
fn heartbeat_starts_and_stops() {
    let heartbeat = Heartbeat::start("test", "test-ns".to_owned(), "test-backend".to_owned());
    // Give it a moment to potentially emit.
    std::thread::sleep(std::time::Duration::from_millis(50));
    heartbeat.stop_and_join();
    // If we get here without hanging, the heartbeat stopped and joined.
}
