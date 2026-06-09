//! G10 — Reorg-deep.
//! **G10 — Reorg-deep test (INTENDED).** A simulated 100-block reorg replays cleanly: UTXO state,
//! coinstats, filter index, electrum index, wallet, and mempool all converge to the new tip without
//! panic, deadlock, or stale row; verified against bitcoind's reorg behavior in regtest.
//!
//! **STATUS — NOT YET IMPLEMENTED.** Node-level chain reorganization does not exist: the apply path
//! advances `applied_tip` forward only (it rejects any non-extending block), undo data is never
//! persisted, and `plan_reorg` has no production caller. The full-stack gate below is therefore
//! `#[ignore]`d until reorg lands. The running test verifies only the reorg *planner* (disconnect /
//! connect list computation), not node-level rollback — it must not be read as evidence that reorg
//! works.

#![allow(clippy::expect_used)]

/// Verifies the reorg PLANNER computes the depth-100 disconnect/connect node lists for a competing
/// fork. Does NOT exercise node-level reorg (UTXO rollback, coinstats, indexes, wallet, mempool) —
/// that behavior is unimplemented; see the ignored full-stack placeholder below.
#[test]
fn reorg_deep_test() {
    let output = std::process::Command::new(env!("CARGO"))
        .args([
            "test",
            "-p",
            "bitcoin-rs-chain",
            "plans_deep_reorg_to_common_fork",
        ])
        .output()
        .expect("spawn cargo");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "chain crate depth-100 reorg planner test failed:\n{stdout}\n{stderr}"
    );
    // Loud-fail guard: `cargo test <name>` exits 0 even when zero tests match (the planner test gets
    // renamed, removed, or cfg-gated away). Require the named test to appear as executed-and-passed in
    // the output so the gate can't pass on zero matches. A substring filter (no `--exact`) plus matching
    // on the `<name> ... ok` suffix stays robust to module nesting; same anti-theater intent as G7.
    assert!(
        stdout.contains("plans_deep_reorg_to_common_fork ... ok"),
        "reorg planner test did not run (renamed/removed?) — gate would be theater:\n{stdout}\n{stderr}"
    );
}

/// INTENDED full-stack reorg gate: a 100-block reorg in which UTXO state, coinstats, filter/electrum
/// indexes, wallet, and mempool all converge to the new tip, cross-checked against bitcoind regtest.
///
/// NOT YET IMPLEMENTED — node-level reorg (block disconnect + UTXO undo) does not exist: `applied_tip`
/// is forward-only, undo data is never persisted, and `plan_reorg` is unwired. Un-ignore and build this
/// once node-level reorg lands; until then it is a placeholder, not a passing check.
#[test]
#[ignore = "node-level reorg unimplemented (forward-only tip, undo not persisted, plan_reorg unwired)"]
fn reorg_deep_fullstack() {
    // Apply a chain, reorg to a competing higher-work branch, and assert UTXO / coinstats / filter /
    // electrum / wallet / mempool state converges to the new tip vs bitcoind regtest. Requires
    // node-level reorg (disconnect + undo) to be implemented first.
}
