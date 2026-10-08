//! In-memory UTXO set for bitcoin-rs.
//!
//! 256 first-byte shards, each a `hashbrown::HashTable` of compact
//! transaction-level records behind a `parking_lot::RwLock`, with a native
//! snapshot format and versioned undo codec.
//!
//! # Surface
//!
//! Chainstate mutates this set through one coherent contract
//! ([`contract`]): build a block's changes, persist and load its undo record,
//! and roll it back on disconnect. Record, shard, event, and codec machinery
//! stays inside the crate; what leaves it is the apply/commit/disconnect
//! contract plus the read, snapshot, and statistics surfaces.

#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// Compact encodings for UTXO record fields.
mod compress;
/// The chainstate-facing apply/commit/disconnect contract.
pub mod contract;
/// UTXO hash-table key.
mod key;

pub(crate) use key::UtxoKey;
/// Commit-event delivery to the coinstats listener.
mod listener;
/// Prevout lookups over the committed set plus prepared-but-uncommitted blocks.
mod overlay;
/// Owned UTXO records.
mod record;
/// UTXO-set mutations and lookup.
pub mod set;
/// Shard internals.
mod shard;
/// Native bitcoin-rs UTXO snapshot format.
pub mod snapshot;
/// Running UTXO-set statistics over the live set above.
pub mod stats;
/// Versioned on-disk encoding for undo records.
mod undo_codec;

pub use overlay::{WindowOverlay, WindowOverlayError};
pub use set::{UtxoCoin, UtxoError, UtxoMemoryReport, UtxoReader, UtxoScan, UtxoSet, UtxoSetView};
pub use snapshot::{
    SnapshotCoin, SnapshotCoinObserver, SnapshotLoad, read_snapshot_strict_v4,
    read_snapshot_strict_v4_observed, write_snapshot_observed,
};
