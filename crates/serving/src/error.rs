use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("{0}")]
    InvalidRequest(&'static str),
    #[error("{0}")]
    TopLevelParse(&'static str),
    #[error("method not found: {0}")]
    MethodNotFound(String),
    #[error("invalid params: {0}")]
    InvalidParams(&'static str),
    #[error("{0}")]
    InvalidType(String),
    #[error("not found: {0}")]
    NotFound(&'static str),
    #[error("{0}")]
    MethodDisabled(&'static str),
    #[error("{0}")]
    InvalidParameter(String),
    #[error("{0}")]
    ScanInProgress(String),
    #[error("{0}")]
    InvalidAddressOrKey(String),
    #[error("{0}")]
    TxRejected(String),
    #[error("{0}")]
    TxVerifyError(String),
    #[error("{0}")]
    Deserialization(String),
    #[error("{0}")]
    ClientNotConnected(String),
    #[error("{0}")]
    ClientInInitialDownload(String),
    #[error("{0}")]
    Misc(String),
    #[error("{0}")]
    CoreInternal(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl RpcError {
    const PARSE_ERROR: i64 = -32_700;
    pub const INVALID_REQUEST: i64 = -32_600;
    pub const METHOD_NOT_FOUND: i64 = -32_601;
    pub const INVALID_PARAMS: i64 = -32_602;
    pub const INTERNAL_ERROR: i64 = -32_603;
    pub(crate) const CORE_INVALID_TYPE: i64 = -3;
    pub const CORE_NOT_FOUND: i64 = -5;
    pub(crate) const CORE_INVALID_PARAMETER: i64 = -8;
    pub const CORE_VERIFY_REJECTED: i64 = -26;
    pub(crate) const CORE_VERIFY_ERROR: i64 = -25;
    pub(crate) const CORE_DESERIALIZATION_ERROR: i64 = -22;
    pub(crate) const CORE_CLIENT_NOT_CONNECTED: i64 = -9;
    pub(crate) const CORE_CLIENT_IN_INITIAL_DOWNLOAD: i64 = -10;

    #[must_use]
    pub const fn code(&self) -> i64 {
        match self {
            Self::Parse(_) | Self::TopLevelParse(_) => Self::PARSE_ERROR,
            Self::Misc(_) => -1,
            Self::InvalidRequest(_) => Self::INVALID_REQUEST,
            Self::MethodNotFound(_) => Self::METHOD_NOT_FOUND,
            Self::InvalidParams(_) => Self::INVALID_PARAMS,
            Self::InvalidType(_) => Self::CORE_INVALID_TYPE,
            Self::NotFound(_) | Self::InvalidAddressOrKey(_) => Self::CORE_NOT_FOUND,
            Self::TxRejected(_) => Self::CORE_VERIFY_REJECTED,
            Self::TxVerifyError(_) => Self::CORE_VERIFY_ERROR,
            Self::Deserialization(_) => Self::CORE_DESERIALIZATION_ERROR,
            Self::InvalidParameter(_) | Self::ScanInProgress(_) => Self::CORE_INVALID_PARAMETER,
            Self::ClientNotConnected(_) => Self::CORE_CLIENT_NOT_CONNECTED,
            Self::ClientInInitialDownload(_) => Self::CORE_CLIENT_IN_INITIAL_DOWNLOAD,
            Self::MethodDisabled(_) | Self::Internal(_) | Self::CoreInternal(_) => {
                Self::INTERNAL_ERROR
            }
        }
    }
}

impl From<core::str::Utf8Error> for RpcError {
    fn from(error: core::str::Utf8Error) -> Self {
        Self::Parse(error.to_string())
    }
}

impl From<sonic_rs::Error> for RpcError {
    fn from(error: sonic_rs::Error) -> Self {
        Self::Parse(error.to_string())
    }
}

impl From<crate::context::TxQueryError> for RpcError {
    fn from(error: crate::context::TxQueryError) -> Self {
        match error {
            crate::context::TxQueryError::Retry => {
                Self::Internal("transaction index is still catching up; retry later".to_owned())
            }
            crate::context::TxQueryError::Unavailable(cause) => {
                Self::Internal(format!("transaction index unavailable: {cause}"))
            }
            crate::context::TxQueryError::Storage(reason) => {
                Self::Internal(format!("transaction index storage error: {reason}"))
            }
        }
    }
}
