#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error("decode error: {0}")]
    Decode(#[from] bitcoin_rs_primitives::DecodeError),
    #[error("hash error: {0}")]
    Hash(#[from] bitcoin_rs_primitives::HashError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("utf8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("json error: {0}")]
    Json(#[from] sonic_rs::Error),
    #[error(
        "missing fixture {height}.{extension}; run scripts/fetch-golden.sh to populate testdata"
    )]
    MissingFixture {
        height: u32,
        extension: &'static str,
    },
    #[error("missing expected value: {0}")]
    Missing(&'static str),
}

impl From<&'static str> for TestError {
    fn from(msg: &'static str) -> Self {
        Self::Missing(msg)
    }
}
