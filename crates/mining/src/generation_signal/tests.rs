// CONTRACT: `docs/contracts/architecture.md#ARCH-07` owns post-commit
// consumer ordering; `MiningGenerationSignal` is the mining wake projection.
use super::MiningGenerationSignal;
use crate::MempoolSequenceWake;
use crate::MiningControl;
use crate::control::FakeMiningControl;
use std::sync::Arc;

#[test]
fn attached_signal_forwards_every_generation_publication() {
    // Detached: nothing to wake, nothing panics.
    let detached = MiningGenerationSignal::new();
    detached.publish_generation();
    detached.publish_generation_from(1);

    let signal = MiningGenerationSignal::new();
    let control = FakeMiningControl::unavailable("not wired in this test");
    let control_dyn: Arc<dyn MiningControl> = control.clone();
    signal.attach(&control_dyn);

    assert_eq!(control.publish_count(), 0);
    signal.publish_generation();
    signal.publish_generation();
    assert_eq!(
        control.publish_count(),
        2,
        "every authoritative-mutation wake must reach the coordinator"
    );
}

#[test]
fn attached_signal_forwards_sequence_wake_without_mempool_lock() {
    let signal = MiningGenerationSignal::new();
    let control = FakeMiningControl::unavailable("not wired in this test");
    let control_dyn: Arc<dyn MiningControl> = control.clone();
    signal.attach(&control_dyn);

    // Without attach_sequence_wake, publish_generation_from falls back.
    signal.publish_generation_from(1);
    assert_eq!(control.publish_count(), 1);
    assert!(control.published_from.lock().is_empty());

    let wake_dyn: Arc<dyn MempoolSequenceWake> = control.clone();
    signal.attach_sequence_wake(&wake_dyn);

    signal.publish_generation_from(7);
    signal.publish_generation_from(8);
    assert_eq!(
        *control.published_from.lock(),
        vec![7, 8],
        "sequence wakes must reach the lock-free path"
    );
    assert_eq!(
        control.publish_count(),
        1,
        "sequence wakes must not fall back to publish_generation"
    );
}
