//! Shared verification support for integration tests and gates.

#![expect(
    dead_code,
    reason = "Support modules are consumed by different integration test binaries; any single binary may leave some helpers unused."
)]

pub(crate) mod reference_set;
