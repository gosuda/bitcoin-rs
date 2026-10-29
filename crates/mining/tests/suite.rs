//! Consumer-boundary tests, grouped into one integration binary.

mod block_limits;
mod coinbase_sigops;
mod coinbase_template;
mod index_selection_oracle;
mod overhaul_resource_bounds;
mod policy_pareto;
#[cfg(feature = "pool")]
mod pool_jobs;
#[cfg(feature = "pool")]
mod pool_sv1;
#[cfg(feature = "pool-sv2")]
mod pool_sv2;
mod raw_sigops;
mod staged_parent_locks;
mod template_shape;
mod witness_commitment_vector;

mod support;
