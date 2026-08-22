//! In-memory UTXO set for bitcoin-rs.
//!
//! The set is split into 256 first-byte shards. Each shard stores compact,
//! transaction-level `UtxoRecord` owners inline in a `hashbrown::HashTable`;
//! every record owns one boxed encoded payload and mutations are guarded by a
//! cache-padded `parking_lot::RwLock`.

#![forbid(unsafe_op_in_unsafe_fn)]

/// Compact encodings for UTXO record fields.
mod compress;
/// UTXO hash-table key.
pub mod key;
/// Owned UTXO records.
pub mod record;
/// UTXO-set mutations and lookup.
pub mod set;
/// Shard internals.
pub mod shard;
/// Native bitcoin-rs UTXO snapshot format.
pub mod snapshot;
/// Versioned on-disk encoding for undo records.
pub mod undo_codec;

pub use key::{UtxoBuildHasher, UtxoKey};
pub use record::{OneUtxoOut, RecordCodec, UtxoRecord};
pub use set::{
    BlockChanges, ScannedUtxo, UndoBatch, UtxoAdd, UtxoChangeListener, UtxoError, UtxoInserted,
    UtxoMemoryReport, UtxoRemoved, UtxoScan, UtxoSet, UtxoSetView,
};
pub use shard::{LiveOutput, LiveOutputMeta};
pub use snapshot::{
    SnapshotCoin, SnapshotCoinObserver, SnapshotLoad, aggregate_hash, hash_serialized_3,
    read_snapshot, read_snapshot_strict_v4_observed, write_snapshot, write_snapshot_observed,
};
pub use undo_codec::{
    UNDO_FORMAT_VERSION, UndoCodecError, decode as decode_undo, encode as encode_undo,
};
