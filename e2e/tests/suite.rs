//! Consumer-boundary tests, grouped into one integration binary.

mod acceptance;
mod assumeutxo;
mod block_spends;
mod chain_queries;
mod deployment_info;
mod http_surfaces;
mod lifecycle;
mod mempool_tx;
mod mining;
mod overlay_connectivity;
mod p2p_sync;
mod peer_discouragement;
mod reorg;
mod reorg_state;
mod rpc_tip_waits;
mod scantxoutset;
mod tx_download;
mod tx_relay_policy;
