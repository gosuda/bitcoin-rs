//! Teardown-entry observation seam.
//!
//! The daemon and embedded paths both enter `NodeServices::teardown`; the
//! seam lets tests prove both entry points reach the same lifecycle without
//! a fake service graph. It compiles away outside tests.

/// Test-only teardown-entry observation seam.
///
/// `NodeServices::teardown` marks entry through the one ordered teardown
/// that the daemon (`run`) and the embedded node (`Node::shutdown`) share.
/// The seam lets a test prove both entry points reach the same lifecycle
/// without a fake service graph; it compiles away outside tests.
#[cfg(test)]
pub(crate) struct ShutdownStageGuard;

#[cfg(test)]
thread_local! {
    static SHUTDOWN_STAGES_REACHED: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
}

/// Marks that the shared teardown ran on this thread; test builds count the
/// entry, non-test builds return a no-op marker.
#[cfg(test)]
#[must_use]
pub(crate) fn mark_shutdown_stage() -> ShutdownStageGuard {
    SHUTDOWN_STAGES_REACHED.with(|slot| slot.set(slot.get().saturating_add(1)));
    ShutdownStageGuard
}

/// Returns and clears the number of shared-teardown entries on this thread.
#[cfg(test)]
pub(crate) fn take_shutdown_stages_reached() -> u32 {
    SHUTDOWN_STAGES_REACHED.with(core::cell::Cell::take)
}

/// Non-test no-op marker so `teardown` carries the same `_stage` binding
/// without compiling the counter.
#[cfg(not(test))]
pub(crate) struct ShutdownStageMark;

#[cfg(not(test))]
#[must_use]
pub(crate) fn mark_shutdown_stage() -> ShutdownStageMark {
    ShutdownStageMark
}
