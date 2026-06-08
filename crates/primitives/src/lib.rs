#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Block wrapper and block-level hashing helpers.
pub mod block;
/// Consensus encoding and hashing helpers shared by primitive wrappers.
pub mod encode;
/// Fixed-width 256-bit hash type.
pub mod hash;
/// Block header wrapper and header hash computation.
pub mod header;
/// Bitcoin network constants.
pub mod network;
/// Fixed-layout transaction outpoint.
pub mod outpoint;
/// Signature-hash mode wrappers.
pub mod sighash;
/// Transaction wrappers and txid/wtxid computation.
pub mod tx;
/// Bitcoin compact-size integer codec.
pub mod varint;
/// Workspace release version constants for wire/RPC user-agent strings.
pub mod version;

pub use block::Block;
pub use hash::{Hash256, HashError};
pub use header::Header;
pub use network::Network;
pub use outpoint::OutPoint;
pub use sighash::{Sighash, SighashError};
pub use tx::{Tx, TxIn, TxOut};
pub use version::{PKG_VERSION, USER_AGENT};
