#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error(transparent)]
    Chain(#[from] bitcoin_rs_chain::ChainError),
    #[error(transparent)]
    RegtestFixture(#[from] bitcoin_rs_chain::regtest_fixture::RegtestFixtureError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    TryFromInt(#[from] core::num::TryFromIntError),
    #[error("missing expected value: {0}")]
    Missing(&'static str),
}

impl From<&'static str> for TestError {
    fn from(msg: &'static str) -> Self {
        Self::Missing(msg)
    }
}
