use std::time::{Duration, Instant};

use super::{BatchWait, wait_for_batch_deadline, wait_for_revision_quiet};
use crate::txindex_worker::TxIndexRuntime;

#[test]
fn coalesced_wakes_still_observe_the_latest_revision() {
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let runtime = TxIndexRuntime::new(sender);
    runtime.wake();
    runtime.wake();
    assert_eq!(receiver.len(), 1);
    assert_eq!(runtime.revision(), 2);
    assert_eq!(
        wait_for_revision_quiet(&runtime, &receiver, Duration::ZERO, 0),
        Some(2)
    );
}

#[test]
fn shutdown_short_circuits_quiet_wait() {
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let runtime = TxIndexRuntime::new(sender);
    runtime.request_shutdown();
    assert_eq!(
        wait_for_revision_quiet(&runtime, &receiver, Duration::ZERO, 0),
        None
    );
}

#[test]
fn shutdown_takes_precedence_over_an_expired_deadline() {
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let runtime = TxIndexRuntime::new(sender);
    let deadline = Instant::now();
    runtime.request_shutdown();
    assert_eq!(
        wait_for_batch_deadline(&runtime, &receiver, deadline),
        BatchWait::Stopped
    );
}

#[test]
fn an_expired_batch_deadline_does_not_wait_for_a_wake() {
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let runtime = TxIndexRuntime::new(sender);
    assert_eq!(
        wait_for_batch_deadline(&runtime, &receiver, Instant::now()),
        BatchWait::Deadline
    );
}

#[test]
fn a_queued_wake_interrupts_the_wait_without_replacing_the_deadline() {
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let runtime = TxIndexRuntime::new(sender);
    let deadline = Instant::now() + Duration::from_secs(60);
    runtime.wake();
    assert_eq!(
        wait_for_batch_deadline(&runtime, &receiver, deadline),
        BatchWait::Woken
    );
    assert_eq!(runtime.revision(), 1);
}
