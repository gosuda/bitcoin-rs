//! Shared verification support for integration tests and gates.
//!
//! Unit tests for these modules live in the sibling `*_tests.rs` files,
//! included only by the `support_unit_tests` target: `#[cfg(test)]` code
//! here would compile — and run — once per embedding binary (issue #1083).

#![expect(
    clippy::expect_used,
    reason = "support code uses expect for unrecoverable test setup failures"
)]
#![expect(
    dead_code,
    reason = "Support modules are consumed by different integration test binaries; any single binary may leave some helpers unused."
)]

pub(crate) mod dependency_graph;
pub(crate) mod ownership_scan;
pub(crate) mod process_node;
pub(crate) mod process_peer;
pub(crate) mod reference_set;
