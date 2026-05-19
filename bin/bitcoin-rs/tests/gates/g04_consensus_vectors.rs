//! G4 — Consensus test vectors.
//! **G4 — Consensus test vectors.** `tx_valid.json`, `tx_invalid.json`, `script_tests.json`, `sighash.json` from Bitcoin Core's `src/test/data/` are vendored into `crates/consensus/tests/vectors/` and run as `#[test]`s; 100 % pass.

#![allow(clippy::expect_used)]

/// Gate G4 re-runs the consensus crate vector tests under the umbrella gate
/// package so `cargo test -p bitcoin-rs` reports the shippability gate.
#[test]
fn consensus_test_vectors() {
    let status = std::process::Command::new(env!("CARGO"))
        .args(["test", "-p", "bitcoin-rs-consensus", "--no-fail-fast"])
        .status()
        .expect("spawn cargo");
    assert!(
        status.success(),
        "consensus crate tests must pass — these include tx_valid.json, tx_invalid.json, script_tests.json, sighash.json"
    );
}
