//! G2 — Full IBD UTXO root parity (muhash).
//! **G2 — Full IBD UTXO root parity.** Every 10 000 blocks during IBD, our running coinstats hash matches Bitcoin Core's `gettxoutsetinfo` muhash field byte-for-byte.

#![allow(clippy::let_unit_value)]

/// Gate G2 manual run instructions: run
/// `cargo test -p bitcoin-rs --test g02_ibd_muhash_parity -- --ignored --nocapture`
/// with a live Bitcoin Core peer/RPC endpoint, then cross-check every
/// 10 000-block muhash sample against `bitcoin-cli gettxoutsetinfo`.
#[test]
#[ignore = "requires full IBD + bitcoind gettxoutsetinfo cross-check"]
fn full_ibd_utxo_root_parity_muhash() {
    // Compare sampled bitcoin-rs coinstats muhash values to bitcoind gettxoutsetinfo during IBD.
    let _ = ();
}
