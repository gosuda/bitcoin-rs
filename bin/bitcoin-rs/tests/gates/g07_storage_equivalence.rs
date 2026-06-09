//! G7 — Storage-backend equivalence.
//! **G7 — Storage-backend equivalence.** `RocksDB`, MDBX (`signet-libmdbx`), fjall, and redb backends all pass G1–G6 with identical chain results. `cargo bench --bench kvstore_backends` reports throughput + p99 latency for all four in `target/bench-report.md`. **Backend promotion rule:** if MDBX wins by ≥15 % on UTXO-commit p95 AND matches `RocksDB` on Electrum-history p95, MDBX becomes the new default in the next minor release and the change is documented in the ultrareview log.

#![allow(clippy::expect_used)]

/// Gate G7 enforces the four-backend aggregate-hash equivalence assertion in
/// `crates/storage/tests/backend_equivalence.rs`. It builds the storage crate
/// with all four backends (rocksdb, fjall, redb, mdbx) and runs
/// `portable_backends_have_identical_aggregate_hashes` by exact name. Running
/// `-p bitcoin-rs-storage` with default features silently compiles the
/// `cfg(all(...))` four-way test out, leaving the gate green without asserting
/// anything — so the gate fails loudly unless the test actually executed.
#[test]
fn storage_backend_equivalence() {
    let output = std::process::Command::new(env!("CARGO"))
        .args([
            "test",
            "-p",
            "bitcoin-rs-storage",
            "--no-default-features",
            "--features",
            "rocksdb,fjall,redb,mdbx",
            "portable_backends_have_identical_aggregate_hashes",
            "--",
            "--exact",
        ])
        .output()
        .expect("spawn cargo");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "four-backend aggregate-hash equivalence test failed:\n{stdout}\n{stderr}"
    );
    // Loud-fail guard: a `cfg(all(rocksdb, fjall, redb))` test silently vanishes
    // if any backend feature is dropped from the invocation. Require evidence it
    // actually ran so the gate can never regress to green-but-empty theater.
    assert!(
        stdout.contains("1 passed"),
        "four-backend equivalence test did not run (compiled out?) — gate would be theater:\n{stdout}\n{stderr}"
    );
}
