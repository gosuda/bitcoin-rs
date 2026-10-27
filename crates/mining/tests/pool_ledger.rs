//! The complete accounting suite runs against each real node storage backend.
mod redb {
    const BACKEND: &str = "redb";
    include!("support/pool_ledger_cases.rs");
}
mod fjall {
    const BACKEND: &str = "fjall";
    include!("support/pool_ledger_cases.rs");
}
