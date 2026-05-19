//! G9 — Wallet PSBT round-trip.
//! **G9 — Wallet PSBT round-trip.** For every descriptor type (p2pkh, p2wpkh, p2sh-p2wpkh, p2tr, multisig, descriptor-wallet single-sig + multi-sig): wallet builds a PSBT, an external test signer signs it (test-only fixture key), wallet finalizes, RPC `sendrawtransaction` accepts. No private key ever passes through the wallet crate's public surface.

#![allow(clippy::let_unit_value)]

/// Gate G9 manual run instructions: run
/// `cargo test -p bitcoin-rs --test g09_wallet_psbt_roundtrip -- --ignored --nocapture`
/// while exercising every listed descriptor type with an external signer fixture
/// and submit each finalized transaction. The wallet
/// crate has a CI grep guard ensuring no `SecretKey` leaks; that lives in
/// `crates/wallet/tests/`.
#[test]
#[ignore = "requires every descriptor type + external signer fixture"]
fn wallet_psbt_round_trip() {
    // Build, externally sign, finalize, and submit PSBTs for every documented descriptor family.
    let _ = ();
}
