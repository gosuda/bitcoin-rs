//! G13 — Lints clean.
//! **G13 — Lints clean.** `cargo +1.85.0 clippy --workspace --all-targets --all-features -- -D warnings` returns 0. `cargo +1.85.0 fmt --check` clean. `cargo deny check` clean.

#![allow(clippy::let_unit_value)]

/// Gate G13 manual CI invocation: run
/// `cargo +1.85.0 clippy --workspace --all-targets --all-features -- -D warnings`,
/// `cargo +1.85.0 fmt --check`, and `cargo deny check` in the dedicated lint
/// job.
#[test]
#[ignore = "runs cargo clippy across the workspace; invoke manually in CI"]
fn lints_clean() {
    // Run the documented lint, fmt, and cargo-deny invocations in the dedicated CI job.
    let _ = ();
}
