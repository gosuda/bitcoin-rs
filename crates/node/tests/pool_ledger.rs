#![cfg(all(feature = "pool", feature = "test-seam"))]

mod rocksdb {
    const BACKEND: &str = "rocksdb";
    include!("support/pool_ledger_cases.rs");
}
