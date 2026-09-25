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

/// Records that the shared teardown ran. Test builds count the entry through
/// the observation seam; other builds record nothing. Both builds share one
/// plain call shape; the guard carries no behavior, so callers drop it.
#[cfg(test)]
pub(crate) fn mark_shutdown_stage() -> ShutdownStageGuard {
    SHUTDOWN_STAGES_REACHED.with(|slot| slot.set(slot.get().saturating_add(1)));
    ShutdownStageGuard
}

/// Returns and clears the number of shared-teardown entries on this thread.
#[cfg(test)]
pub(crate) fn take_shutdown_stages_reached() -> u32 {
    SHUTDOWN_STAGES_REACHED.with(core::cell::Cell::take)
}

/// Non-test builds record nothing.
#[cfg(not(test))]
pub(crate) fn mark_shutdown_stage() {}
