//! G17 - One-way crate dependency direction.
//!
//! See `docs/contracts/architecture.md` clauses `ARCH-01` through `ARCH-04`.
//!
//! This gate reuses `tests/support/dependency_graph.rs` so the same parser and
//! validator is available to `overhaul_ownership.rs` for synthetic negative
//! cases.

#![expect(
    clippy::expect_used,
    reason = "cargo metadata subprocess and JSON parse failures are unrecoverable in this gate"
)]

use std::io::Write as _;

#[path = "../support/mod.rs"]
mod support;

use support::dependency_graph::{BIN_CRATE, Validation, WorkspaceGraph};

#[test]
fn workspace_dependency_direction_is_one_way() {
    let graph = WorkspaceGraph::from_cargo_metadata();
    let Validation {
        checked_edges,
        checked_engine_edges,
        checked_features,
        classified,
        summary,
    } = graph
        .validate()
        .expect("workspace dependency graph is valid");

    let _ = writeln!(
        std::io::stderr(),
        "G17: {summary} | crates: {classified} | binary: {BIN_CRATE}"
    );

    assert!(checked_edges > 0, "no internal edges were checked");
    assert!(
        classified >= 12,
        "workspace crates went missing from metadata: {classified} classified"
    );
    assert!(
        checked_engine_edges == 0 || graph.engine_deps.contains_key("bitcoin-rs-storage"),
        "engine edges found on crates other than storage"
    );
    assert!(
        checked_features > 0,
        "no feature forwarding assertions were checked"
    );
}
