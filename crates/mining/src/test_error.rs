#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error(transparent)]
    Chain(#[from] bitcoin_rs_chain::ChainError),
    #[error(transparent)]
    Mining(#[from] crate::MiningError),
    #[error(transparent)]
    MiningControl(#[from] crate::control::MiningControlError),
    #[error(transparent)]
    Mempool(#[from] bitcoin_rs_mempool::MempoolError),
    #[error(transparent)]
    Prioritise(#[from] bitcoin_rs_mempool::PrioritiseError),
    #[cfg(feature = "pool")]
    #[error(transparent)]
    Ledger(#[from] crate::pool::ledger::LedgerError),
    #[cfg(feature = "pool")]
    #[error(transparent)]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error(transparent)]
    BitcoinDecode(#[from] bitcoin::consensus::encode::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    TryFromInt(#[from] core::num::TryFromIntError),
    #[error(transparent)]
    RecvTimeout(#[from] std::sync::mpsc::RecvTimeoutError),
    #[error("missing expected value: {0}")]
    Missing(&'static str),
}

impl From<&'static str> for TestError {
    fn from(msg: &'static str) -> Self {
        Self::Missing(msg)
    }
}
