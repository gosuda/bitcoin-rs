#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error("decode error: {0}")]
    Decode(#[from] crate::encode::DecodeError),
    #[error("hash error: {0}")]
    Hash(#[from] crate::hash::HashError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("try-from-int error: {0}")]
    TryFromInt(#[from] core::num::TryFromIntError),
    #[error("missing expected value: {0}")]
    Missing(&'static str),
}

impl From<&'static str> for TestError {
    fn from(msg: &'static str) -> Self {
        Self::Missing(msg)
    }
}
