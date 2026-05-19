use core::fmt;
use std::io;

use sonic_rs::{Value, json};
use thiserror::Error;

/// JSON-RPC 2.0 and Bitcoin Core-compatible RPC errors.
#[derive(Debug, Error)]
pub enum RpcError {
    /// JSON text could not be parsed.
    #[error("parse error: {0}")]
    Parse(String),
    /// Request object is not a valid JSON-RPC call.
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    /// Method name is not supported.
    #[error("method not found: {0}")]
    MethodNotFound(String),
    /// Parameters have the wrong shape.
    #[error("invalid params: {0}")]
    InvalidParams(&'static str),
    /// Parameter value has the wrong JSON type.
    #[error("invalid type: {0}")]
    InvalidType(&'static str),
    /// Requested object was not found.
    #[error("not found: {0}")]
    NotFound(&'static str),
    /// A method is intentionally disabled by policy.
    #[error("{0}")]
    MethodDisabled(&'static str),
    /// Internal server failure.
    #[error("internal error: {0}")]
    Internal(String),
}

impl RpcError {
    /// Standard JSON-RPC parse error code.
    pub const PARSE_ERROR: i64 = -32_700;
    /// Standard JSON-RPC invalid request code.
    pub const INVALID_REQUEST: i64 = -32_600;
    /// Standard JSON-RPC unknown method code.
    pub const METHOD_NOT_FOUND: i64 = -32_601;
    /// Standard JSON-RPC invalid params code.
    pub const INVALID_PARAMS: i64 = -32_602;
    /// Standard JSON-RPC internal error code.
    pub const INTERNAL_ERROR: i64 = -32_603;
    /// Bitcoin Core invalid type code.
    pub const CORE_INVALID_TYPE: i64 = -3;
    /// Bitcoin Core not-found code.
    pub const CORE_NOT_FOUND: i64 = -5;
    /// Bitcoin Core invalid parameter value code.
    pub const CORE_INVALID_PARAMETER: i64 = -8;

    /// Builds the no-private-keys policy error used by signing RPCs.
    #[must_use]
    pub const fn method_disabled(message: &'static str) -> Self {
        Self::MethodDisabled(message)
    }

    /// Returns the JSON-RPC numeric error code.
    #[must_use]
    pub const fn code(&self) -> i64 {
        match self {
            Self::Parse(_) => Self::PARSE_ERROR,
            Self::InvalidRequest(_) => Self::INVALID_REQUEST,
            Self::MethodNotFound(_) => Self::METHOD_NOT_FOUND,
            Self::InvalidParams(_) => Self::INVALID_PARAMS,
            Self::InvalidType(_) => Self::CORE_INVALID_TYPE,
            Self::NotFound(_) => Self::CORE_NOT_FOUND,
            Self::MethodDisabled(_) | Self::Internal(_) => Self::INTERNAL_ERROR,
        }
    }

    /// Converts this error into a JSON-RPC response object for `id`.
    #[must_use]
    pub fn response(&self, id: &Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "result": null,
            "error": {"code": self.code(), "message": self.to_string()},
            "id": id
        })
    }
}

impl From<sonic_rs::Error> for RpcError {
    fn from(error: sonic_rs::Error) -> Self {
        Self::Parse(error.to_string())
    }
}

impl From<serde_json::Error> for RpcError {
    fn from(error: serde_json::Error) -> Self {
        Self::Internal(error.to_string())
    }
}

impl From<io::Error> for RpcError {
    fn from(error: io::Error) -> Self {
        Self::Internal(error.to_string())
    }
}

impl From<bitcoin::consensus::encode::Error> for RpcError {
    fn from(_error: bitcoin::consensus::encode::Error) -> Self {
        Self::InvalidParams("consensus decoding failed")
    }
}

impl From<bitcoin::hex::HexToBytesError> for RpcError {
    fn from(_error: bitcoin::hex::HexToBytesError) -> Self {
        Self::InvalidParams("hex string is invalid")
    }
}

impl From<core::str::Utf8Error> for RpcError {
    fn from(error: core::str::Utf8Error) -> Self {
        Self::Parse(error.to_string())
    }
}

impl From<fmt::Error> for RpcError {
    fn from(error: fmt::Error) -> Self {
        Self::Internal(error.to_string())
    }
}
