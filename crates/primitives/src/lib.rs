#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Native block type and block-level hashing helpers.
pub mod block;
/// Chain-level policy constants shared across tiers.
pub mod chain_constants;
/// Wall-clock readings as whole UNIX seconds.
pub mod clock;
/// Native consensus encoding and decoding for protocol types.
pub mod encode;
/// Fixed-width 256-bit hash type.
pub mod hash;
/// Native block header type and header hash computation.
pub mod header;
/// Generic byte-slice hex encoding and decoding.
pub mod hex;
/// Transaction, witness-transaction, and block identifier newtypes.
pub mod ids;
/// Checked borrowed wire layout for blocks and transactions.
pub mod layout;
/// Bitcoin network constants.
pub mod network;
/// Saturating integer casts and an exact `u64` to `f64` conversion.
pub mod numeric;
/// Fixed-layout transaction outpoint.
pub mod outpoint;
/// Native script and witness byte stacks.
pub mod script;
/// Native signature-hash computation for legacy, segwit v0, and taproot.
pub mod sighash;
/// Native transaction types and txid/wtxid computation.
pub mod tx;
/// Native protocol scalar newtypes: amount, sequence, locktime, compact target.
pub mod units;
/// Bitcoin compact-size integer codec.
pub mod varint;
/// Workspace release version constants for wire/RPC user-agent strings.
pub mod version;

pub use block::Block;
pub use clock::{unix_now, unix_seconds};
pub use encode::{
    ConsensusDecode, ConsensusEncode, DecodeError, Sink, consensus_bytes, consensus_len,
    deserialize,
};
pub use hash::{Hash256, HashError};
pub use header::Header;
pub use hex::{HexDecodeError, hex_decode, hex_encode};
pub use ids::{BlockHash, Txid, Wtxid};
pub use network::{ChainTxData, HeadersSyncParams, Network};
pub use numeric::{
    i64_saturated, i64_saturated_len, u32_saturated, u32_saturated_len, u64_saturated_len,
    u64_to_f64,
};
pub use outpoint::OutPoint;
pub use script::{MAX_SCRIPT_SIZE, Script, Witness};
pub use sighash::{
    AnnexError, CODESEPARATOR_POSITION, Sighash, SighashCache, SighashError,
    TAPSCRIPT_LEAF_VERSION, tapleaf_hash,
};
pub use tx::{Tx, TxIn, TxOut};
pub use units::{
    Amount, CompactTarget, ExpandedTarget, LOCKTIME_THRESHOLD, LockTime, SEQUENCE_FINAL,
    SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_GRANULARITY_SECONDS, SEQUENCE_LOCKTIME_MASK,
    SEQUENCE_LOCKTIME_TYPE_FLAG, Sequence,
};
pub use version::{PKG_VERSION, USER_AGENT, client_version};
