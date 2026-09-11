//! IDX-07: supervision owns namespace release after terminal worker outcomes.

use super::*;

/// IDX-07: a detached backend may still access the namespace after its worker exits.
#[test]
fn abandoned_open_outcomes_poison_the_namespace_before_release() -> std::io::Result<()> {
    for error in [
        TxIndexWorkerError::OpenStopped,
        TxIndexWorkerError::OpenTimeout { secs: 1 },
    ] {
        let dir = tempfile::tempdir()?;
        let key = dir.path().join("txindex");
        let generation = Generation::new(1);
        let runtime = TxIndexRuntime::new(crossbeam_channel::bounded(1).0);
        let lifecycle = Arc::new(ArcSwap::from_pointee(TxIndexLifecycle::Opening));
        assert!(NAMESPACE_REGISTRY.claim(key.clone(), generation.id()));
        finish_worker(&runtime, &lifecycle, &generation, &key, Err(error));
        assert!(runtime.should_stop());
        assert!(matches!(**lifecycle.load(), TxIndexLifecycle::Failed(_)));
        assert!(NAMESPACE_REGISTRY.is_poisoned(&key));
        assert!(!NAMESPACE_REGISTRY.claim(key, 2));
    }
    Ok(())
}

/// IDX-07: completed workers and failures with no detached helper can release.
#[test]
fn completed_worker_outcomes_release_without_poisoning() -> std::io::Result<()> {
    for result in [
        Ok(()),
        Err(TxIndexWorkerError::Stopped),
        Err(TxIndexWorkerError::NoBodyStore),
    ] {
        let dir = tempfile::tempdir()?;
        let key = dir.path().join("txindex");
        let generation = Generation::new(1);
        let runtime = TxIndexRuntime::new(crossbeam_channel::bounded(1).0);
        let lifecycle = Arc::new(ArcSwap::from_pointee(TxIndexLifecycle::Opening));
        assert!(NAMESPACE_REGISTRY.claim(key.clone(), generation.id()));
        finish_worker(&runtime, &lifecycle, &generation, &key, result);
        assert!(!NAMESPACE_REGISTRY.is_poisoned(&key));
        assert!(NAMESPACE_REGISTRY.claim(key.clone(), 2));
        NAMESPACE_REGISTRY.release(&key, 2);
    }
    Ok(())
}
