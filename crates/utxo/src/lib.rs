//! In-memory UTXO set for bitcoin-rs.
//!
//! The set is split into 256 first-byte shards. Each shard stores immutable
//! transaction-level records in a `self_cell!`-pinned `bumpalo::Bump` arena,
//! indexes them with `hashbrown::HashTable`, and guards mutation with a
//! cache-padded `parking_lot::RwLock`.

#![forbid(unsafe_op_in_unsafe_fn)]

/// Round-robin shard defragmentation.
pub mod defrag;
/// UTXO hash-table key.
pub mod key;
/// Arena-resident UTXO records.
pub mod record;
/// UTXO-set mutations and lookup.
pub mod set;
/// Shard internals.
pub mod shard;
/// Native bitcoin-rs UTXO snapshot format.
pub mod snapshot;

pub use key::{UtxoBuildHasher, UtxoKey};
pub use record::{OneUtxoOut, UtxoRecord};
pub use set::{
    BlockChanges, ScannedUtxo, UndoBatch, UtxoAdd, UtxoChangeListener, UtxoError, UtxoRemoved,
    UtxoScan, UtxoSet, UtxoSetView,
};
pub use shard::{LiveOutput, LiveOutputMeta};
pub use snapshot::{
    SnapshotLoad, aggregate_hash, hash_serialized_3, read_snapshot, write_snapshot,
};
