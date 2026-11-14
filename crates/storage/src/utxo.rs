#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod compress;
pub mod contract;
pub mod core_snapshot;
mod key;

pub(crate) use key::UtxoKey;
pub mod record;
pub mod scan;
pub mod set;
mod shard;
pub mod snapshot;
pub mod stats;
#[cfg(test)]
pub(crate) mod test_support;
mod undo_codec;

pub use compress::{
    compress_amount, decompress_amount, read_varint, varint_len, write_varint_into,
};
pub use record::UtxoRecord;
pub use set::{UtxoCoin, UtxoError, UtxoMemoryReport, UtxoReader, UtxoScan, UtxoSet, UtxoSetView};
pub use snapshot::{
    PairObserver, SeedProvenance, SnapshotCoin, SnapshotCoinObserver, SnapshotLoad, V4Witness,
    VerifiedSnapshotArtifact, read_snapshot_strict_v4, read_snapshot_strict_v4_observed,
    read_snapshot_strict_v4_witnessed, write_snapshot_observed, write_snapshot_witnessed,
};
