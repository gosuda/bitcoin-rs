//! Single owner of the unit tests for the shared `tests/support` modules.
//!
//! The support modules are embedded by every integration-test binary through
//! `mod support;`, so `#[cfg(test)]` code inside them would compile — and its
//! tests run — once per embedding binary (issue #1083). The test bodies live
//! in sibling `*_tests.rs` files under `tests/support/` that only this target
//! includes, so each assertion runs once per profile.

#![expect(
    clippy::expect_used,
    reason = "test setup and fixture failures are unrecoverable here"
)]

#[path = "support/mod.rs"]
mod support;

#[path = "support/ownership_scan_tests.rs"]
mod ownership_scan_tests;

#[path = "support/process_node_tests.rs"]
mod process_node_tests;

#[path = "support/process_peer_tests.rs"]
mod process_peer_tests;
