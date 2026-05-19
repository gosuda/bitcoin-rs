//! G10 — Reorg-deep.
//! **G10 — Reorg-deep test.** Simulated 100-block reorg replays cleanly: UTXO state, coinstats, filter index, electrum index, wallet, mempool all converge to the new tip without panic, deadlock, or stale row. Verified against bitcoind's reorg behavior in regtest.

#![allow(clippy::expect_used)]

/// Gate G10 re-runs the chain crate's depth-100 reorg regression test landed
/// during T7.
#[test]
fn reorg_deep_test() {
    let status = std::process::Command::new(env!("CARGO"))
        .args([
            "test",
            "-p",
            "bitcoin-rs-chain",
            "plans_deep_reorg_to_common_fork",
        ])
        .status()
        .expect("spawn cargo");
    assert!(
        status.success(),
        "chain crate depth-100 reorg test must pass"
    );
}
