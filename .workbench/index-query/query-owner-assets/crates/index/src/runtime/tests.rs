//! IDX-03: the worker and query engine share one health/revision source.

use super::*;

#[test]
fn coalesced_wakes_still_advance_every_revision() {
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let runtime = TxIndexRuntime::new(sender);
    for _ in 0..8 {
        runtime.wake();
    }
    assert_eq!(runtime.revision(), 8);
    assert_eq!(receiver.try_iter().count(), 1);
    assert!(!runtime.should_stop());
}

#[test]
fn disconnected_wake_receiver_does_not_hide_revision_or_shutdown() {
    let (sender, receiver) = crossbeam_channel::bounded(1);
    drop(receiver);
    let runtime = TxIndexRuntime::new(sender);
    runtime.wake();
    runtime.request_shutdown();
    assert_eq!(runtime.revision(), 1);
    assert!(runtime.should_stop());
    assert!(runtime.is_shutdown());
    assert!(!runtime.is_failed());
}

#[test]
fn shutdown_is_nonblocking_when_the_wake_channel_is_full() {
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let runtime = TxIndexRuntime::new(sender);
    runtime.wake();
    runtime.request_shutdown();
    assert!(runtime.is_shutdown());
    assert_eq!(runtime.revision(), 1);
    assert_eq!(receiver.try_iter().count(), 1);
}

#[test]
fn failure_stops_queries_and_keeps_the_published_diagnostic() {
    let (sender, _receiver) = crossbeam_channel::bounded(1);
    let runtime = TxIndexRuntime::new(sender);
    runtime.publish_failed("unreadable index");
    assert!(runtime.is_failed());
    assert!(runtime.should_stop());
    assert_eq!(runtime.failure_message().as_deref(), Some("unreadable index"));
    assert!(!runtime.is_shutdown());
}

#[test]
fn publishing_one_capability_phase_preserves_its_siblings() {
    let (sender, _receiver) = crossbeam_channel::bounded(1);
    let runtime = TxIndexRuntime::new(sender);
    runtime.publish_leg(IndexCapabilities::SCRIPT_HISTORY, ReconcileLeg::Rebuilding);
    let phase = runtime.phase();
    assert_eq!(phase.script_history, ReconcileLeg::Rebuilding);
    assert_eq!(phase.script_live, ReconcileLeg::Forward);
    assert_eq!(phase.tx_lookup, ReconcileLeg::Forward);
    runtime.publish_phase(ReconcilePhase::FORWARD);
    assert_eq!(runtime.phase(), ReconcilePhase::FORWARD);
}
