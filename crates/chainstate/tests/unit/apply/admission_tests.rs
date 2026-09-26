use arc_swap::ArcSwapOption;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use super::ApplyAdmission;
use super::Chainstate;
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

/// The recovery-closed read is the queryable form of the fatal-failure
/// state: it flips exactly when `fail_closed_for_recovery` closes
/// admission, and it is its own operational fact — never an initial-block-
/// download answer, and independent of any chain height.
#[test]
fn is_closed_for_recovery_tracks_the_fatal_close() {
    let chainstate = Chainstate::new(
        bitcoin_rs_primitives::Network::Regtest,
        Arc::new(ArcSwapOption::empty()),
        Arc::new(ArcSwapOption::empty()),
        Arc::new(parking_lot::RwLock::new(bitcoin_rs_chain::BlockTree::new())),
        Arc::new(bitcoin_rs_utxo::UtxoSet::new()),
        Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::default(),
        )),
        Arc::new(crate::events::ChainEventPublisher::detached(0)),
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
        chainstate.lock_transition().is_err(),
        "the same closure still refuses every later transition"
    );
}
