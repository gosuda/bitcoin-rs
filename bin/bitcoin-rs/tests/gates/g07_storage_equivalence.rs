//! G7 — Storage-backend equivalence.
//! **G7 — Storage-backend equivalence.** `RocksDB`, MDBX (`signet-libmdbx`), fjall, and redb backends all pass G1–G6 with identical chain results. `cargo bench --bench kvstore_backends` reports throughput + p99 latency for all four in `target/bench-report.md`. **Backend promotion rule:** if MDBX wins by ≥15 % on UTXO-commit p95 AND matches `RocksDB` on Electrum-history p95, MDBX becomes the new default in the next minor release and the change is documented in the ultrareview log.

#![allow(clippy::expect_used)]

/// Gate G7 re-runs the storage crate tests; the 4-backend aggregate hash
/// equivalence assertion lives in `crates/storage/tests/backend_equivalence.rs`.
#[test]
fn storage_backend_equivalence() {
    let status = std::process::Command::new(env!("CARGO"))
        .args(["test", "-p", "bitcoin-rs-storage", "--no-fail-fast"])
        .status()
        .expect("spawn cargo");
    assert!(
        status.success(),
        "storage crate tests must pass — backend_equivalence.rs asserts 4-backend aggregate hash equivalence"
    );
}
