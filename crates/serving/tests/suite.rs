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

mod mining_block_limits;
mod mining_coinbase_sigops;
mod mining_coinbase_template;
mod mining_index_selection_oracle;
mod mining_overhaul_resource_bounds;
mod mining_policy_pareto;
#[cfg(feature = "pool")]
mod mining_pool_jobs;
#[cfg(feature = "pool")]
mod mining_pool_sv1;
#[cfg(feature = "pool-sv2")]
mod mining_pool_sv2;
mod mining_raw_sigops;
mod mining_template_shape;
mod mining_witness_commitment_vector;

mod mining_fixture;
#[allow(dead_code)]
mod support;

pub use bitcoin_rs_serving::mining;
