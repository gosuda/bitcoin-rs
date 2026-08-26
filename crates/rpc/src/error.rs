use core::fmt;
use std::io;

use thiserror::Error;

/// JSON-RPC 2.0 and Bitcoin Core-compatible RPC errors.
#[derive(Debug, Error)]
pub enum RpcError {
    /// JSON text could not be parsed or the top-level value was neither an
    /// object nor an array; carries Core's exact wire message.
    #[error("{0}")]
    Parse(String),
    /// Request object is not a valid JSON-RPC call.
    #[error("{0}")]
    InvalidRequest(&'static str),
    /// Method name is not supported.
    #[error("method not found: {0}")]
    MethodNotFound(String),
    /// Parameters have the wrong shape.
    #[error("{0}")]
    InvalidParams(&'static str),
    /// A named parameter is unknown, duplicated, or conflicts with a positional value.
    #[error("{0}")]
    InvalidParameter(String),
    /// Parameter value has the wrong JSON type.
    #[error("{0}")]
    InvalidType(&'static str),
    /// Requested object was not found.
    #[error("{0}")]
    NotFound(&'static str),
    /// A method is intentionally disabled by policy.
    #[error("{0}")]
    MethodDisabled(&'static str),
    /// RPC server has not finished starting.
    #[error("{0}")]
    InWarmup(String),
    /// RPC server is shutting down.
    #[error("Shutting down")]
    ClientNotConnected,
    /// A caught command failure with no more specific Core category.
    #[error("{0}")]
    Misc(String),
    /// Transaction hex or consensus decoding failed.
    #[error("{0}")]
    Deserialization(String),
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
    /// Bitcoin Core miscellaneous error code.
    pub const CORE_MISC_ERROR: i64 = -1;
    /// Bitcoin Core invalid type code.
    pub const CORE_INVALID_TYPE: i64 = -3;
    /// Bitcoin Core not-found code.
    pub const CORE_NOT_FOUND: i64 = -5;
    /// Bitcoin Core invalid parameter value code.
    pub const CORE_INVALID_PARAMETER: i64 = -8;
    /// Bitcoin Core client-not-connected code.
    pub const CORE_CLIENT_NOT_CONNECTED: i64 = -9;
    /// Bitcoin Core warmup code.
    pub const CORE_IN_WARMUP: i64 = -28;
    /// Bitcoin Core deserialization error code.
    pub const CORE_DESERIALIZATION_ERROR: i64 = -22;

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
            Self::InvalidParameter(_) => Self::CORE_INVALID_PARAMETER,
            Self::InvalidType(_) => Self::CORE_INVALID_TYPE,
            Self::NotFound(_) => Self::CORE_NOT_FOUND,
            Self::MethodDisabled(_) | Self::Internal(_) => Self::INTERNAL_ERROR,
            Self::InWarmup(_) => Self::CORE_IN_WARMUP,
            Self::ClientNotConnected => Self::CORE_CLIENT_NOT_CONNECTED,
            Self::Misc(_) => Self::CORE_MISC_ERROR,
            Self::Deserialization(_) => Self::CORE_DESERIALIZATION_ERROR,
        }
    }

    /// Returns the exact message included in a Core-compatible error object.
    #[must_use]
    pub fn wire_message(&self) -> &str {
        match self {
            Self::MethodNotFound(_) => "Method not found",
            Self::ClientNotConnected => "Shutting down",
            Self::InvalidRequest(message)
            | Self::InvalidParams(message)
            | Self::InvalidType(message)
            | Self::NotFound(message)
            | Self::MethodDisabled(message) => message,
            Self::Parse(message)
            | Self::InvalidParameter(message)
            | Self::InWarmup(message)
            | Self::Misc(message)
            | Self::Deserialization(message)
            | Self::Internal(message) => message,
        }
    }
}

impl From<sonic_rs::Error> for RpcError {
    fn from(_error: sonic_rs::Error) -> Self {
        // Core reports exactly "Parse error"; parser detail is logged by the
        // request lifecycle owner, never leaked onto the wire.
        Self::Parse("Parse error".to_owned())
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
    fn from(_error: core::str::Utf8Error) -> Self {
        Self::Parse("Parse error".to_owned())
    }
}

impl From<fmt::Error> for RpcError {
    fn from(error: fmt::Error) -> Self {
        Self::Internal(error.to_string())
    }
}

impl From<crate::context::TxQueryError> for RpcError {
    fn from(error: crate::context::TxQueryError) -> Self {
        error.into_rpc_error()
    }
}

#[cfg(test)]
mod tests {
    use super::RpcError;

    #[test]
    fn core_error_codes_and_wire_messages_are_stable() {
        let cases = [
            (
                RpcError::Parse("Parse error".to_owned()),
                -32_700,
                "Parse error",
            ),
            (
                RpcError::Parse("Top-level object parse error".to_owned()),
                -32_700,
                "Top-level object parse error",
            ),
            (
                RpcError::InvalidRequest("Invalid Request object"),
                -32_600,
                "Invalid Request object",
            ),
            (
                RpcError::MethodNotFound("secret_method".to_owned()),
                -32_601,
                "Method not found",
            ),
            (
                RpcError::InvalidParams("wrong number of parameters"),
                -32_602,
                "wrong number of parameters",
            ),
            (
                RpcError::InvalidParameter("duplicate argument".to_owned()),
                -8,
                "duplicate argument",
            ),
            (
                RpcError::InvalidType("expected a number"),
                -3,
                "expected a number",
            ),
            (RpcError::NotFound("block not found"), -5, "block not found"),
            (
                RpcError::MethodDisabled("wallet has no private keys; use external signer"),
                -32_603,
                "wallet has no private keys; use external signer",
            ),
            (
                RpcError::InWarmup("Loading block index…".to_owned()),
                -28,
                "Loading block index…",
            ),
            (RpcError::ClientNotConnected, -9, "Shutting down"),
            (
                RpcError::Misc("uncaught command failure".to_owned()),
                -1,
                "uncaught command failure",
            ),
            (
                RpcError::Deserialization("TX decode failed".to_owned()),
                -22,
                "TX decode failed",
            ),
        ];

        for (error, code, message) in cases {
            assert_eq!(error.code(), code);
            assert_eq!(error.wire_message(), message);
        }
    }

    #[test]
    fn malformed_json_conversions_report_the_core_parse_message() {
        let malformed = match sonic_rs::from_str::<sonic_rs::Value>("{") {
            Ok(value) => panic!("malformed json must not parse: {value:?}"),
            Err(error) => RpcError::from(error),
        };
        assert_eq!(malformed.code(), RpcError::PARSE_ERROR);
        assert_eq!(malformed.wire_message(), "Parse error");
    }
}
