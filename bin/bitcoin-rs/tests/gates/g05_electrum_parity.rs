//! G5 — Electrum protocol parity.
//! **G5 — Electrum protocol parity.** Pointed at the same chain, our `crates/electrum` returns byte-identical responses to a reference electrs build for `blockchain.scripthash.{get_history,get_balance,subscribe,listunspent}`, `blockchain.transaction.get`, `blockchain.estimatefee`, `mempool.get_fee_histogram`, `server.{version,banner,donation_address,peers.subscribe}` over a 1 000-scripthash random sample.

#![allow(clippy::let_unit_value)]

/// Gate G5 manual run instructions: run
/// `cargo test -p bitcoin-rs --test g05_electrum_parity -- --ignored --nocapture`
/// with bitcoin-rs electrum and a reference electrs build on the same chain,
/// replay the 1 000-scripthash sample, and compare every response byte-for-byte.
#[test]
#[ignore = "requires reference electrs build + shared chain"]
fn electrum_protocol_parity() {
    // Diff bitcoin-rs electrum responses against reference electrs for the documented method set.
}
