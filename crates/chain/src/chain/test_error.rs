#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error(transparent)]
    Chain(#[from] crate::chain::ChainError),
    #[error(transparent)]
    AncestryBudget(#[from] crate::chain::AncestryBudgetExceeded),
    #[error(transparent)]
    DeploymentQuery(#[from] crate::chain::deployment::DeploymentQueryError),
    #[cfg(feature = "test-seam")]
    #[error(transparent)]
    RegtestFixture(#[from] crate::chain::regtest_fixture::RegtestFixtureError),
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
