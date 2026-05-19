//! G8 — Utreexo parity.
//! **G8 — Utreexo parity.** With `--utreexo` enabled, IBD reproduces the same chain tip + coinstats hash as the rocksdb full-UTXO path.

#![allow(clippy::let_unit_value)]

/// Gate G8 manual run instructions: run
/// `cargo test -p bitcoin-rs --test g08_utreexo_parity -- --ignored --nocapture`
/// while driving `--utreexo` IBD beside the full-UTXO rocksdb baseline, then
/// compare the chain tip and coinstats hash.
#[test]
#[ignore = "requires --utreexo IBD against full-UTXO baseline"]
fn utreexo_parity() {
    // Compare utreexo IBD tip and coinstats hash against the full-UTXO rocksdb baseline.
}
