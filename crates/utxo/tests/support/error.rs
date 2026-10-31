#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    Utxo(#[from] bitcoin_rs_utxo::UtxoError),
    #[error(transparent)]
    RawSeed(#[from] bitcoin_rs_utxo::RawSeedError<std::convert::Infallible>),
    #[error(transparent)]
    CoinStatsDecode(#[from] bitcoin_rs_utxo::stats::CoinStatsDecodeError),
    #[error("missing: {0}")]
    Missing(&'static str),
    #[error("unexpected success: {0}")]
    UnexpectedSuccess(&'static str),
}

pub(crate) type TestResult<T = ()> = Result<T, TestError>;
