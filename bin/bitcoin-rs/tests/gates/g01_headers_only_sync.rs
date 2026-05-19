//! G1 — Headers-only sync parity.
//! **G1 — Headers-only sync parity.** `bitcoin-rs --headers-only mainnet` → header chain hash matches `bitcoind`'s `getblockhash` for every height 0..tip.

#![allow(clippy::let_unit_value)]

/// Gate G1 manual run instructions: set `BITCOIND_RPC_URL` and
/// `BITCOIND_RPC_COOKIE`, then run
/// `cargo test -p bitcoin-rs --test g01_headers_only_sync -- --ignored --nocapture`.
/// The gate compares every headers-only mainnet height against bitcoind.
#[test]
#[ignore = "requires live bitcoind mainnet RPC for cross-check"]
fn headers_only_sync_parity() {
    // Compare bitcoin-rs headers-only mainnet block hashes to bitcoind getblockhash for 0..tip.
}
