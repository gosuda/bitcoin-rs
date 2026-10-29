//! Consumer-boundary tests, grouped into one integration binary.

mod addrman_restart_e2e;
mod block_inputs;
mod compact_blocks_e2e;
#[path = "gates/g17_dependency_direction.rs"]
mod g17_dependency_direction;
mod head_sync_e2e;
mod large_undo_startup;
mod live_head_carried_e2e;
mod mempool_expiry_capacity;
mod mempool_restart;
mod overhaul_external_miner;
mod overhaul_process_harness;
mod overhaul_process_p2p;
mod rest_getutxos_process;
mod silent_payments;
mod tx_ibd_gate_e2e;
mod verifychain_block_rules;
mod wallet_facing;

mod support;
