//! Consumer-boundary tests, grouped into one integration binary.

mod auth;
mod core_compat;
mod core_parity;
mod esplora_fee_estimates;
mod handler_smoke;
mod manifest_coverage;
mod policy_contract;
mod reorg_notifications;
mod scantxoutset_lifecycle;
mod setban_expiry;
mod tip_wait_admission;
mod transaction_methods;

mod mining_fixture;
#[allow(dead_code)]
mod support;
