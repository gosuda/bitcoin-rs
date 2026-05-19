//! G11 — Crash recovery.
//! **G11 — Crash recovery.** `kill -9` during block commit; restart; node converges to the last fully-committed tip and reports no DB corruption (`RocksDB` / fjall / redb each tested).

#![allow(clippy::expect_used)]

/// Gate G11 re-runs the node crate crash-recovery integration test.
#[test]
fn crash_recovery() {
    let status = std::process::Command::new(env!("CARGO"))
        .args(["test", "-p", "bitcoin-rs-node", "--test", "crash_recovery"])
        .status()
        .expect("spawn cargo");
    assert!(
        status.success(),
        "node crash_recovery integration test must pass"
    );
}
