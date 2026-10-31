//! Consumer-boundary tests, grouped into one integration binary.

mod admission;
mod graph_limits;
mod policy_contract;
mod rbf_bip125;
mod replacement_profile;
mod standardness_spend;
mod test_error;
pub use test_error::TestError;
