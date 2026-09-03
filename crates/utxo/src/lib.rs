//! In-memory UTXO set for bitcoin-rs.
//!
//! 256 first-byte shards, each a `hashbrown::HashTable` of compact
//! transaction-level records behind a `parking_lot::RwLock`, with a native
//! snapshot format and versioned undo codec.

#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// Compact encodings for UTXO record fields.
mod compress;
/// UTXO connect accounting: block mutation, undo, and value totals.
pub mod connect;
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
/// Running UTXO-set statistics over the live set above.
pub mod stats;
/// Versioned on-disk encoding for undo records.
pub mod undo_codec;

pub use connect::{BlockChangeError, BlockValueTotals, SpentOutputLookup, is_coinbase_tx};
pub use key::{UtxoBuildHasher, UtxoKey};
pub use record::{OneUtxoOut, UtxoRecord};
pub use set::{
    BlockChanges, BorrowedBlockChanges, BorrowedUtxoAdd, ScannedUtxo, UndoBatch, UtxoAdd,
    UtxoChangeEvents, UtxoChangeListener, UtxoCommittedEvent, UtxoError, UtxoInserted,
    UtxoMemoryReport, UtxoRemoved, UtxoScan, UtxoSet, UtxoSetView,
};
pub use shard::{LiveOutput, LiveOutputMeta};
pub use snapshot::{
    SnapshotCoin, SnapshotCoinObserver, SnapshotLoad, aggregate_hash, hash_serialized_3,
    read_snapshot_strict_v4, read_snapshot_strict_v4_observed, write_snapshot,
    write_snapshot_observed,
};
pub use undo_codec::{
    UNDO_FORMAT_VERSION, UndoCodecError, decode as decode_undo, encode as encode_undo,
};
