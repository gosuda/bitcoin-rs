#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error(transparent)]
    Mining(#[from] bitcoin_rs_mining::MiningError),
    #[error(transparent)]
    MiningControl(#[from] bitcoin_rs_mining::MiningControlError),
    #[error(transparent)]
    Mempool(#[from] bitcoin_rs_mempool::MempoolError),
    #[error(transparent)]
    Prioritise(#[from] bitcoin_rs_mempool::PrioritiseError),
    #[error(transparent)]
    Submit(#[from] bitcoin_rs_mempool::SubmitError),
    #[error(transparent)]
    ChainChange(#[from] bitcoin_rs_mempool::ChainChangeError),
    #[error(transparent)]
    Rbf(#[from] bitcoin_rs_mempool::RbfError),
    #[error(transparent)]
    Consensus(#[from] bitcoin_rs_consensus::ConsensusError),
    #[cfg(feature = "pool")]
    #[error(transparent)]
    Job(#[from] bitcoin_rs_mining::pool::JobError),
    #[cfg(feature = "pool")]
    #[error(transparent)]
    Share(#[from] bitcoin_rs_mining::pool::ShareError),
    #[cfg(feature = "pool")]
    #[error(transparent)]
    SessionOpen(#[from] bitcoin_rs_mining::pool::SessionOpenError),
    #[cfg(feature = "pool")]
    #[error(transparent)]
    Sv1Config(#[from] bitcoin_rs_mining::pool::stratum::sv1::ConfigError),
    #[cfg(feature = "pool-sv2")]
    #[error(transparent)]
    Sv2Config(#[from] bitcoin_rs_mining::pool::stratum::sv2::ConfigError),
    #[cfg(feature = "pool-sv2")]
    #[error(transparent)]
    Sv2Transport(#[from] bitcoin_rs_mining::pool::stratum::sv2::TransportError),
    #[cfg(feature = "pool-sv2")]
    #[error(transparent)]
    Sv2(#[from] bitcoin_rs_mining::pool::stratum::sv2::Error),
    #[cfg(feature = "pool-sv2")]
    #[error(transparent)]
    Session(#[from] bitcoin_rs_mining::pool::stratum::sv2::SessionError),
    #[cfg(feature = "pool-sv2")]
    #[error("codec sv2 error: {0:?}")]
    Codec(codec_sv2::Error),
    #[cfg(feature = "pool-sv2")]
    #[error("noise sv2 error: {0:?}")]
    Noise(noise_sv2::Error),
    #[cfg(feature = "pool-sv2")]
    #[error("binary sv2 error: {0:?}")]
    BinarySv2(binary_sv2::Error),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    BitcoinDecode(#[from] bitcoin::consensus::encode::Error),
    #[error(transparent)]
    Json(#[from] sonic_rs::Error),
    #[cfg(feature = "pool")]
    #[error("fixture transaction {label} was not committed")]
    Uncommitted { label: u8 },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    TryFromInt(#[from] core::num::TryFromIntError),
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
    #[error(transparent)]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error(transparent)]
    TryFromSlice(#[from] core::array::TryFromSliceError),
    #[error("missing expected value: {0}")]
    Missing(&'static str),
}

impl From<&'static str> for TestError {
    fn from(msg: &'static str) -> Self {
        Self::Missing(msg)
    }
}
#[cfg(feature = "pool-sv2")]
impl From<codec_sv2::Error> for TestError {
    fn from(err: codec_sv2::Error) -> Self {
        Self::Codec(err)
    }
}

#[cfg(feature = "pool-sv2")]
impl From<noise_sv2::Error> for TestError {
    fn from(err: noise_sv2::Error) -> Self {
        Self::Noise(err)
    }
}

#[cfg(feature = "pool-sv2")]
impl From<binary_sv2::Error> for TestError {
    fn from(err: binary_sv2::Error) -> Self {
        Self::BinarySv2(err)
    }
}
