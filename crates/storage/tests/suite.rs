//! Consumer-boundary tests, grouped into one integration binary.

mod backend_equivalence;
mod backend_metrics;
mod batch_range_ordering;
mod bounded_prefix_scan;
mod bounded_value_read;
mod cache_budget;
mod durable_head_store;
mod kv_store_object_safety;
mod overhaul_atomic_durability;
mod prune_then_reorg;
mod redb_txindex;
mod store_guard;
