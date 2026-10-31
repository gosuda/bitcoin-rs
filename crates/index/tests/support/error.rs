#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error(transparent)]
    Index(#[from] bitcoin_rs_index::IndexError),
    #[error(transparent)]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sonic(#[from] sonic_rs::Error),
    #[error(transparent)]
    Decode(#[from] bitcoin_rs_primitives::DecodeError),
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    HexToBytes(#[from] bitcoin::hex::HexToBytesError),
    #[error(transparent)]
    HexToArray(#[from] bitcoin::hex::HexToArrayError),
    #[error(transparent)]
    BlockSpends(#[from] bitcoin_rs_utxo::contract::BlockSpendsError),
    #[error(transparent)]
    HistoryUnavailable(#[from] bitcoin_rs_utxo::contract::HistoryUnavailable),
    #[cfg(feature = "silent-payments")]
    #[error(transparent)]
    Tweak(#[from] bitcoin_rs_index::silent_payments::TweakError),
    #[error("missing {0}")]
    Missing(&'static str),
}

impl From<&'static str> for TestError {
    fn from(s: &'static str) -> Self {
        Self::Missing(s)
    }
}
