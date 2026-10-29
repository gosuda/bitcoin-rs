//! Consumer-boundary tests, grouped into one integration binary.

mod chainstate_journal;
mod config_layered;
mod embed;
mod lease_registration_215;
mod mining;
mod overhaul_durable_head;
mod overhaul_fee_history;
mod shutdown;
mod state_storage;
mod sync_smoke;
mod tx_ingress_e2e;
