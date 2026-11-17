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
pub(crate) mod test_support {
    #[derive(Debug, thiserror::Error)]
    pub(crate) enum TestError {
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        TryFromInt(#[from] std::num::TryFromIntError),
        #[error(transparent)]
        Storage(#[from] crate::StorageError),
        #[error(transparent)]
        Utxo(#[from] crate::utxo::set::UtxoError),
        #[error(transparent)]
        BlockSpends(#[from] crate::utxo::contract::BlockSpendsError),
        #[error(transparent)]
        UndoCodec(#[from] crate::utxo::undo_codec::UndoCodecError),
        #[error(transparent)]
        UndoLoad(#[from] crate::utxo::contract::UndoLoadError),
        #[error(transparent)]
        Snapshot(#[from] crate::utxo::core_snapshot::SnapshotError),
        #[error(transparent)]
        StateVerify(#[from] crate::utxo::core_snapshot::StateVerifyError),
        #[error("missing: {0}")]
        Missing(&'static str),
    }

    pub(crate) type TestResult<T = ()> = Result<T, TestError>;
}
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
