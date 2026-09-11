//! Shared verification support for integration tests and gates.

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
