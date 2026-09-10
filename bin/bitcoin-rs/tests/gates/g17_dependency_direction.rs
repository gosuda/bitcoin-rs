//! G17 — One-way crate dependency direction.
//!
//! **G17 — Dependency direction.** The workspace crates form a one-way layer
//! model; `cargo metadata` proves every edge points the approved way, no crate
//! outside `bitcoin-rs-storage` names a storage-engine dependency
//! (`rust-rocksdb`, `fjall`, `redb`, `signet-libmdbx`), and the RPC crate
//! names no storage backend at all — neither as a dependency nor as a
//! forwarded cargo feature.
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
//! - The engine rule is the storage-boundary rule: only the storage crate may
//!   name a backend engine. Everything above talks to the `KvStore` facade.
//! - Backend *feature* forwarding is confined to the operator-facing tiers
//!   (node, binary) and the services-tier adapters; rpc forwards none.
//!
//! The gate fails loudly, naming the offending edge, when any assertion does
//! not hold.
//!
//! Contract: `docs/contracts/architecture.md` —
//! `workspace_dependency_direction_is_one_way` pins `ARCH-01` (one-way
//! layer edges), `ARCH-02` (engine-crate exclusivity), `ARCH-03` (backend
//! feature-forwarding confinement), and `ARCH-04` (RPC storage
//! independence).
//!
//! The layer table, metadata parser, and validation rules live in exactly one
//! place — `tests/support/dependency_graph.rs`, shared with
//! `overhaul_ownership`. This gate only drives the shared validator over the
//! live workspace metadata so the two can never disagree.

#[path = "../support/mod.rs"]
mod support;

use support::dependency_graph::WorkspaceGraph;

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
        }
        Err(violations) => {
            panic!(
                "dependency direction violations:\n{}",
                violations.join("\n")
            );
        }
    }
}
