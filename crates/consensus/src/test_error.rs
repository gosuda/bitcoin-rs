#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error("consensus error: {0}")]
    Consensus(#[from] crate::ConsensusError),
    #[error("decode error: {0}")]
    Decode(#[from] bitcoin_rs_primitives::DecodeError),
    #[error("try-from-int error: {0}")]
    TryFromInt(#[from] core::num::TryFromIntError),
    #[error("parse-int error: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("missing expected value: {0}")]
    Missing(&'static str),
}

impl From<&'static str> for TestError {
    fn from(msg: &'static str) -> Self {
        Self::Missing(msg)
    }
}
