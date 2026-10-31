#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error("mempool error: {0}")]
    Mempool(#[from] crate::MempoolError),
    #[error("prioritise error: {0}")]
    Prioritise(#[from] crate::PrioritiseError),
    #[error("rbf error: {0}")]
    Rbf(#[from] crate::RbfError),
    #[error("refusal: {0}")]
    Refusal(#[from] crate::rbf::Refusal),
    #[error("submit error: {0}")]
    Submit(#[from] crate::SubmitError),
    #[error("acceptance reject: {0:?}")]
    AcceptanceReject(#[from] crate::standardness::AcceptanceRejectReason),
    #[error("chain change error: {0}")]
    ChainChange(#[from] crate::ChainChangeError),
    #[error("hash error: {0}")]
    Hash(#[from] bitcoin_rs_primitives::HashError),
    #[error("try-from-int error: {0}")]
    TryFromInt(#[from] core::num::TryFromIntError),
    #[error("consensus decode error: {0}")]
    Consensus(#[from] bitcoin::consensus::encode::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("recv timeout error: {0}")]
    RecvTimeout(#[from] std::sync::mpsc::RecvTimeoutError),
    #[error("send error: {0}")]
    Send(#[from] std::sync::mpsc::SendError<()>),
    #[error("infallible")]
    Infallible(#[from] core::convert::Infallible),
    #[error("missing expected value: {0}")]
    Missing(&'static str),
}

impl From<&'static str> for TestError {
    fn from(msg: &'static str) -> Self {
        Self::Missing(msg)
    }
}
