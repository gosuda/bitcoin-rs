#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed note in {path}: {reason}")]
    MalformedNote { path: String, reason: &'static str },
    #[error("missing expected value: {0}")]
    Missing(&'static str),
}
