use std::sync::{Arc, mpsc};
use std::time::Duration;

use super::ApplyAdmission;
use crate::ApplyError;

#[test]
fn shutdown_closes_admission_and_waits_for_in_flight_apply() {
    let admission = Arc::new(ApplyAdmission::new());
    let Ok(in_flight) = admission.enter() else {
        panic!("initial apply must be admitted");
    };
    let closing = Arc::clone(&admission);
    let (tx, rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let _exclusive = closing.close();
        assert!(tx.send(()).is_ok());
    });

    assert!(rx.recv_timeout(Duration::from_millis(20)).is_err());
    drop(in_flight);
    assert!(rx.recv_timeout(Duration::from_secs(1)).is_ok());
    assert!(thread.join().is_ok());
    assert!(matches!(admission.enter(), Err(ApplyError::Shutdown)));
}

#[test]
fn is_closed_for_recovery_tracks_the_fatal_close() {
    let chainstate = crate::test_fixtures::handles(
        bitcoin_rs_consensus::primitives::Network::Regtest,
        Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
    );
    assert!(
        !chainstate.is_closed_for_recovery(),
        "a fresh chainstate is open for mutation"
    );
    chainstate.fail_closed_for_recovery();
    assert!(
        chainstate.is_closed_for_recovery(),
        "failing closed must surface as the queryable recovery-closed fact"
    );
    assert!(
        matches!(chainstate.lock_transition(), Err(ApplyError::Shutdown)),
        "the same closure still refuses every later transition"
    );
}

#[test]
fn shutdown_reader_unblocks_select_on_request_shutdown() {
    let chainstate = crate::test_fixtures::handles(
        bitcoin_rs_consensus::primitives::Network::Regtest,
        Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
    );
    let reader = chainstate.shutdown_reader();
    let (ready_tx, ready_rx) = crossbeam_channel::bounded(1);
    let (tx, rx) = crossbeam_channel::bounded(1);
    let thread = std::thread::spawn(move || {
        let _ = ready_tx.send(());
        crossbeam_channel::select! {
            recv(reader.closed()) -> _ => {
                let _ = tx.send(true);
            }
        }
    });
    assert!(ready_rx.recv_timeout(Duration::from_secs(5)).is_ok());
    chainstate.request_shutdown();
    let unblocked = rx.recv_timeout(Duration::from_secs(5));
    assert!(
        unblocked.is_ok(),
        "select did not unblock on request_shutdown"
    );
    let _ = thread.join();
}

#[test]
fn closed_for_recovery_reader_unblocks_select_on_fail_closed() {
    let chainstate = crate::test_fixtures::handles(
        bitcoin_rs_consensus::primitives::Network::Regtest,
        Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
    );
    let reader = chainstate.closed_for_recovery_reader();
    let (ready_tx, ready_rx) = crossbeam_channel::bounded(1);
    let (tx, rx) = crossbeam_channel::bounded(1);
    let thread = std::thread::spawn(move || {
        let _ = ready_tx.send(());
        crossbeam_channel::select! {
            recv(reader.closed()) -> _ => {
                let _ = tx.send(true);
            }
        }
    });
    assert!(ready_rx.recv_timeout(Duration::from_secs(5)).is_ok());
    chainstate.fail_closed_for_recovery();
    let unblocked = rx.recv_timeout(Duration::from_secs(5));
    assert!(
        unblocked.is_ok(),
        "select did not unblock on fail_closed_for_recovery"
    );
    let _ = thread.join();
}

// ARCH-09
#[test]
fn shutdown_hooks_run_without_the_tip_gate() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let chainstate = Arc::new(crate::test_fixtures::handles(
        bitcoin_rs_consensus::primitives::Network::Regtest,
        Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
    ));
    let gate_free = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&gate_free);
    let owner = Arc::clone(&chainstate);
    let _hook = chainstate.shutdown_reader().on_cancel(move || {
        observed.store(
            owner.tip_notification.gate.try_lock().is_some(),
            Ordering::SeqCst,
        );
    });
    chainstate.request_shutdown();
    assert!(
        gate_free.load(Ordering::SeqCst),
        "cancellation hooks must run without the tip gate held"
    );
}

// RCV-14
#[test]
fn recovery_closure_does_not_upgrade_an_apply_permit() {
    let admission = Arc::new(ApplyAdmission::new());
    let closing = Arc::clone(&admission);
    let (tx, rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let Ok(_permit) = closing.enter() else {
            panic!("initial apply must be admitted");
        };
        closing.close_permanently();
        let _ = tx.send(());
    });
    assert!(rx.recv_timeout(Duration::from_secs(2)).is_ok());
    assert!(thread.join().is_ok());
    assert!(admission.is_closed());
    assert!(matches!(admission.enter(), Err(ApplyError::Shutdown)));
}

// RCV-14, SYNC-04
#[test]
fn recovery_closure_hooks_can_reenter_after_publication_unlocks() {
    let chain = Arc::new(crate::test_fixtures::handles(
        bitcoin_rs_consensus::primitives::Network::Regtest,
        Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
    ));
    let owner = Arc::clone(&chain);
    let _hook = chain.closed_for_recovery_reader().on_cancel(move || {
        assert!(owner.is_closed_for_recovery());
        owner.fail_closed_for_recovery();
    });
    let closing = Arc::clone(&chain);
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        closing.fail_closed_for_recovery();
        let _ = tx.send(());
    });
    assert!(
        rx.recv_timeout(Duration::from_secs(2)).is_ok(),
        "recovery closure must return after its cancellation hook reenters closure"
    );
    assert!(worker.join().is_ok());
    assert!(chain.shutdown_reader().is_triggered());
    assert!(matches!(chain.lock_transition(), Err(ApplyError::Shutdown)));
}
