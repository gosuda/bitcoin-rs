#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Native block type and block-level hashing helpers.
pub mod block;
/// Chain-level policy constants shared across tiers.
pub mod chain_constants;
/// Native consensus encoding and decoding for protocol types.
pub mod encode;
/// Fixed-width 256-bit hash type.
pub mod hash;
/// Native block header type and header hash computation.
pub mod header;
/// Transaction, witness-transaction, and block identifier newtypes.
pub mod ids;
/// Bitcoin network constants.
pub mod network;
/// Fixed-layout transaction outpoint.
pub mod outpoint;
/// Native signature-hash computation for legacy, segwit v0, and taproot.
pub mod sighash;
/// Native transaction types and txid/wtxid computation.
pub mod tx;
/// Bitcoin compact-size integer codec.
pub mod varint;
/// Workspace release version constants for wire/RPC user-agent strings.
pub mod version;

pub use block::Block;
pub use encode::{ConsensusDecode, ConsensusEncode, DecodeError, consensus_bytes, deserialize};
pub use hash::{Hash256, HashError};
pub use header::Header;
pub use ids::{BlockHash, Txid, Wtxid};
pub use network::{ChainTxData, Network};
pub use outpoint::OutPoint;
pub use sighash::{
    AnnexError, CODESEPARATOR_POSITION, Sighash, SighashCache, SighashError,
    TAPSCRIPT_LEAF_VERSION, tapleaf_hash,
};
pub use tx::{Tx, TxIn, TxOut};
pub use version::{PKG_VERSION, USER_AGENT, client_version};
