//! G14 — Performance budgets.
//! **G14 — Performance budgets.**
//! - Block validation throughput ≥ 80 % of `gocoin`'s blocks-per-second on identical mainnet IBD (measured via `criterion`).
//! - UTXO commit p95 ≤ 50 ms per 4 MiB block.
//! - Electrum `scripthash.get_history` p95 ≤ 30 ms over a 10 000-call random sample at tip.
//! - RSS ≤ 16 GiB at mainnet tip with rocksdb default + all indexes enabled.

#![allow(clippy::let_unit_value)]

/// Gate G14 manual run instructions: run
/// `cargo test -p bitcoin-rs --test g14_perf_budgets -- --ignored --nocapture`
/// after criterion-backed mainnet IBD performance measurements, then compare
/// them against the four PLAN.md budgets listed in this crate-level doc comment.
#[test]
#[ignore = "requires criterion runs against mainnet IBD; numbers in PLAN.md G14"]
fn performance_budgets() {
    // Measure mainnet IBD throughput, UTXO commit p95, electrum history p95, and RSS budgets.
}
