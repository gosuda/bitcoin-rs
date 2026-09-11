//! IDX-07 / IDX-08: cancellation is bounded without pretending to cancel a backend.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

#[test]
fn pending_open_rechecks_shutdown_before_the_open_deadline() {
    let (open_tx, open_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let checks = AtomicUsize::new(0);
        let result = wait_for_open_result(&open_rx, Duration::from_secs(30), || {
            // Stop on the second check, after one pending receive. No scheduler
            // race or storage-engine sleep is needed to put the wait in flight.
            checks.fetch_add(1, Ordering::Relaxed) > 0
        });
        let _ = done_tx.send(result);
    });
    let result = done_rx.recv_timeout(Duration::from_secs(2));
    // Unblock even the old, uncapped receive before asserting, so a regression
    // fails promptly rather than leaking a 30-second test thread.
    drop(open_tx);
    assert!(worker.join().is_ok());
    assert!(matches!(result, Ok(Err(TxIndexWorkerError::OpenStopped))));
}

#[test]
fn shutdown_wins_over_an_expired_open_deadline() {
    let (_tx, rx) = mpsc::channel();
    assert!(matches!(
        wait_for_open_result(&rx, Duration::ZERO, || true),
        Err(TxIndexWorkerError::OpenStopped)
    ));
}

#[test]
fn expired_open_deadline_is_typed() {
    let (_tx, rx) = mpsc::channel();
    assert!(matches!(
        wait_for_open_result(&rx, Duration::ZERO, || false),
        Err(TxIndexWorkerError::OpenTimeout { secs: 0 })
    ));
}

#[test]
fn disconnected_open_helper_is_a_storage_failure() {
    let (tx, rx) = mpsc::channel();
    drop(tx);
    assert!(matches!(
        wait_for_open_result(&rx, Duration::from_secs(1), || false),
        Err(TxIndexWorkerError::Storage(bitcoin_rs_storage::StorageError::Backend(reason)))
            if reason == "txindex open helper thread exited without result"
    ));
}

#[test]
fn backend_error_is_preserved_without_becoming_abandonment() {
    let (tx, rx) = mpsc::channel();
    assert!(tx.send(Err(TxIndexWorkerError::Storage(
        bitcoin_rs_storage::StorageError::InvalidOperation("backend sentinel")
    ))).is_ok());
    assert!(matches!(
        wait_for_open_result(&rx, Duration::from_secs(1), || false),
        Err(TxIndexWorkerError::Storage(bitcoin_rs_storage::StorageError::InvalidOperation("backend sentinel")))
    ));
}

#[test]
fn shutdown_before_helper_creation_never_touches_the_store() -> std::io::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("must-not-be-created");
    let result = open_tx_index_with_timeout(
        bitcoin_rs_storage::StorageBackend::Fjall,
        &path,
        8 << 20,
        1,
        Duration::ZERO,
        Duration::from_secs(30),
        || true,
    );
    assert!(matches!(result, Err(TxIndexWorkerError::Stopped)));
    assert!(!path.exists());
    Ok(())
}
