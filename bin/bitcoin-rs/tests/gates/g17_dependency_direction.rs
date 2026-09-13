//! G17 — One-way crate dependency direction and single-writer boundaries.
//!
//! **G17 — Dependency direction and ownership.** The workspace crates form a
//! one-way, acyclic layer model; `cargo metadata` proves every edge points the
//! approved way, `bitcoin-rs-mempool` never depends on its transaction consumers,
//! no crate outside `bitcoin-rs-storage` names a storage-engine dependency
//! (`rust-rocksdb`, `fjall`, `redb`), the RPC crate names no storage backend at
//! all, and the static source scan confirms single-writer mutation boundaries:
//! mempool pool mutations through the gateway, derived-index capability selection,
//! peer registration/cancellation, chainstate transition promotion, and the mempool
//! pressure-floor owner (POL-06).
//!
//! Approved layer direction (a crate may depend only on crates in the same or
//! a strictly lower layer):
//!
//! ```text
//!   layer 0  core       consensus, script, primitives
//!   layer 1  storage    storage
//!   layer 2  services   chain, chainstate, utxo, p2p, mempool, index, mining
//!   layer 3  surface    rpc
//!   layer 4  compose    node, bin (bitcoin-rs)
//! ```
//!
//! Notes that keep this model honest rather than aspirational:
//! - `chain` and `utxo` depend on `storage` (undo records, snapshots), so they
//!   sit in the services layer, not core.
//! - `mining` depends on `mempool` and `chain`; all three live in services.
//! - `chain` depends on `consensus` for BIP9 parameters and the BIP113 cutoff.
//! - `rpc` may consume node capabilities (`index`, `mining`, `mempool`,
//!   `chain`, `utxo`, `p2p`) but never `node` or the binary, and never names a
//!   storage backend.
//! - `mempool` must not depend on `p2p`, `rpc`, `node`, or the binary:
//!   consumers and composition depend on the mempool, not the reverse.
//! - The engine rule is the storage-boundary rule: only the storage crate may
//!   name a backend engine. Everything above talks to the `KvStore` facade.
//! - Backend *feature* forwarding is confined to the operator-facing tiers
//!   (node, binary) and the services-tier adapters that actually select an
//!   engine; rpc, consensus, script, mempool, and mining define none.
//! - Chainstate transition promotion (`lock_transition`,
//!   `begin_transition_locked`) is owned by the node crate; it may not be called
//!   from production code outside `crates/node/src/`.
//!
//! The gate fails loudly, naming the offending edge or source site, when any
//! assertion does not hold.
//!
//! Contract: `docs/contracts/architecture.md` —
//! `workspace_dependency_direction_is_one_way` pins `ARCH-01` (one-way,
//! acyclic layer edges and mempool consumer direction), `ARCH-02` (engine-crate
//! exclusivity), `ARCH-03` (backend feature-forwarding confinement), and
//! `ARCH-04` (RPC storage independence); `workspace_single_writer_boundaries_are_respected`
//! pins `ARCH-07` (chainstate transition owner) and `POL-06` (mempool pressure-floor
//! single owner).
//!
//! The layer table, metadata parser, validation rules, and source-scan rules
//! live in exactly one place — `tests/support/dependency_graph.rs` and
//! `tests/support/ownership_scan.rs`, shared with `overhaul_ownership`. This
//! gate only drives the shared validators over the live workspace metadata and
//! source tree so the two can never disagree.

#[path = "../support/mod.rs"]
mod support;

use support::dependency_graph::WorkspaceGraph;
use support::ownership_scan::{OwnershipScanResult, scan_ownership_violations};

#[test]
fn workspace_dependency_direction_is_one_way() {
    let graph = WorkspaceGraph::from_cargo_metadata();
    assert!(
        graph.classified >= 12,
        "workspace crates went missing from metadata: {} classified",
        graph.classified
    );
    match graph.validate() {
        Ok(report) => {
            assert!(
                report.checked_edges > 0 && report.checked_features > 0,
                "validator checked nothing: {}",
                report.summary
            );
            assert!(
                report.cycle_checked_crates >= 12,
                "cycle check did not run: {}",
                report.summary
            );
        }
        Err(violations) => {
            panic!(
                "dependency direction violations:\n{}",
                violations.join("\n")
            );
        }
    }
}

#[test]
fn workspace_single_writer_boundaries_are_respected() {
    let OwnershipScanResult {
        mempool_writer_violations,
        index_capability_violations,
        peer_owner_violations,
        transition_owner_violations,
        pressure_floor_owner_violations,
        files_scanned,
        ..
    } = scan_ownership_violations();
    assert!(
        files_scanned >= 100,
        "the ownership scan saw only {files_scanned} files; the workspace walk \
         collapsed"
    );
    assert!(
        mempool_writer_violations.is_empty(),
        "mempool single-writer boundary violations: {mempool_writer_violations:?}"
    );
    assert!(
        index_capability_violations.is_empty(),
        "index capability boundary violations: {index_capability_violations:?}"
    );
    assert!(
        peer_owner_violations.is_empty(),
        "peer owner boundary violations: {peer_owner_violations:?}"
    );
    assert!(
        transition_owner_violations.is_empty(),
        "chainstate transition owner boundary violations: {transition_owner_violations:?}"
    );
    assert!(
        pressure_floor_owner_violations.is_empty(),
        "mempool pressure-floor owner boundary violations: {pressure_floor_owner_violations:?}"
    );
}
