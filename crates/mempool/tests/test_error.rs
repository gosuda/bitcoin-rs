use bitcoin_rs_mempool::{AdmitError, MempoolError, PrioritiseError, RbfError, SubmitError};

#[derive(Debug, thiserror::Error)]
pub enum TestError {
    #[error("mempool error: {0}")]
    Mempool(#[from] MempoolError),
    #[error("prioritise error: {0}")]
    Prioritise(#[from] PrioritiseError),
    #[error("rbf error: {0}")]
    Rbf(#[from] RbfError),
    #[error("admit error: {0}")]
    Admit(#[from] AdmitError),
    #[error("submit error: {0}")]
    Submit(#[from] SubmitError),
    #[error("try-from-int error: {0}")]
    TryFromInt(#[from] core::num::TryFromIntError),
    #[error("consensus decode error: {0}")]
    Consensus(#[from] bitcoin::consensus::encode::Error),
    #[error("missing expected value: {0}")]
    Missing(&'static str),
}

impl From<&'static str> for TestError {
    fn from(msg: &'static str) -> Self {
        Self::Missing(msg)
    }
}
