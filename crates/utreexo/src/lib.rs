#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Stump and Pollard accumulator wrapper.
pub mod accumulator;
/// Full bridge-node accumulator support.
pub mod bridge;
/// Public Utreexo proof type.
pub mod proof;

pub use accumulator::{Accumulator, AccumulatorKind, UtreexoError};
pub use bridge::{Bridge, BridgeError};
pub use proof::Proof;
