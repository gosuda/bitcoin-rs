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
        bitcoin_rs_primitives::Network::Regtest,
        Arc::new(bitcoin_rs_utxo::UtxoSet::new()),
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
        bitcoin_rs_primitives::Network::Regtest,
        Arc::new(bitcoin_rs_utxo::UtxoSet::new()),
    );
    let reader = chainstate.shutdown_reader();
    let (tx, rx) = crossbeam_channel::bounded(1);
    let thread = std::thread::spawn(move || {
        crossbeam_channel::select! {
            recv(reader.closed()) -> _ => {
                let _ = tx.send(true);
            }
        }
    });
    std::thread::sleep(Duration::from_millis(50));
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
        bitcoin_rs_primitives::Network::Regtest,
        Arc::new(bitcoin_rs_utxo::UtxoSet::new()),
    );
    let reader = chainstate.closed_for_recovery_reader();
    let (tx, rx) = crossbeam_channel::bounded(1);
    let thread = std::thread::spawn(move || {
        crossbeam_channel::select! {
            recv(reader.closed()) -> _ => {
                let _ = tx.send(true);
            }
        }
    });
    std::thread::sleep(Duration::from_millis(50));
    chainstate.fail_closed_for_recovery();
    let unblocked = rx.recv_timeout(Duration::from_secs(5));
    assert!(
        unblocked.is_ok(),
        "select did not unblock on fail_closed_for_recovery"
    );
    let _ = thread.join();
}
