#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// BIP157 compact-filter header chaining.
pub mod cfheaders;
/// BIP157/158 compact-filter storage index.
pub mod filter_index;
/// BIP158 Golomb-coded set codec.
pub mod gcs;

pub use filter_index::{FilterIndex, FilterIndexError};
