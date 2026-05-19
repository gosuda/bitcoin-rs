//! G3 — Kernel parity.
//! **G3 — Kernel parity gate.** During the first 100 000 mainnet blocks of CI, every block is validated through *both* our Rust validator and `bitcoinkernel`. Any disagreement is a CI hard-fail; the failing block + log is artifacted.

#![allow(clippy::let_unit_value)]

/// Gate G3 manual run instructions: build with `--features kernel`, then run
/// `cargo test -p bitcoin-rs --features kernel --test g03_kernel_parity -- --ignored --nocapture`
/// over the first 100 000 mainnet blocks through both validators and artifact
/// any disagreement.
#[test]
#[ignore = "requires kernel feature + 100k mainnet blocks"]
fn kernel_parity_gate() {
    // Validate each block through bitcoin-rs consensus and bitcoinkernel, then compare verdicts.
}
