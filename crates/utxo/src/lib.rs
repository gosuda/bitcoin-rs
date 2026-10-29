//! In-memory UTXO set for bitcoin-rs.

#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod compress;
pub mod contract;
pub mod core_snapshot;
mod key;

pub(crate) use key::UtxoKey;
mod listener;
mod overlay;
mod record;
pub mod scan;
pub mod set;
mod shard;
pub mod snapshot;
pub mod stats;
mod undo_codec;

pub use overlay::{WindowOverlay, WindowOverlayError};
pub use set::{UtxoCoin, UtxoError, UtxoMemoryReport, UtxoReader, UtxoScan, UtxoSet, UtxoSetView};
pub use snapshot::{
    OfferOutcome, RawSeedError, SeedOfferCell, SeedProvenance, SeedSlot, SnapshotCoin,
    SnapshotCoinObserver, SnapshotLoad, V4Witness, VerifiedSnapshotArtifact,
    read_snapshot_strict_v4, read_snapshot_strict_v4_observed, read_snapshot_strict_v4_witnessed,
    write_snapshot_observed, write_snapshot_witnessed,
};
