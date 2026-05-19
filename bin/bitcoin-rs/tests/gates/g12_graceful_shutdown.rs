//! G12 — Graceful shutdown.
//! **G12 — Graceful shutdown.** SIGTERM during IBD → all in-flight writes flush, RPC connections drain with 5 s deadline, snapshot written, exit code 0. Verified via `criterion` + a regression `#[test]` driving signal-hook.

#![allow(clippy::expect_used)]

/// Gate G12 re-runs the node crate graceful-shutdown integration test.
#[test]
fn graceful_shutdown() {
    let status = std::process::Command::new(env!("CARGO"))
        .args(["test", "-p", "bitcoin-rs-node", "--test", "shutdown"])
        .status()
        .expect("spawn cargo");
    assert!(status.success(), "node shutdown integration test must pass");
}
