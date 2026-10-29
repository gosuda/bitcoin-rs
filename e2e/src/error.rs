//! Error types shared by the e2e harness.

use std::fmt;
use std::path::PathBuf;

use sonic_rs::JsonValueTrait as _;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Json(sonic_rs::Error),
    Rpc {
        method: String,
        code: i64,
        message: String,
    },
    ChildExit {
        pid: u32,
        status: std::process::ExitStatus,
        evidence: PathBuf,
    },
    Timeout {
        pid: u32,
        operation: &'static str,
        evidence: PathBuf,
        detail: String,
    },
    Protocol(String),
    Reference {
        path: PathBuf,
        expected: String,
        detail: String,
    },
    Difference {
        observation: String,
        reference: sonic_rs::Value,
        candidate: sonic_rs::Value,
    },
    Assertion(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "io: {error}"),
            Self::Json(error) => write!(f, "json: {error}"),
            Self::Rpc {
                method,
                code,
                message,
            } => write!(f, "rpc {method} rejected ({code}): {message}"),
            Self::ChildExit {
                pid,
                status,
                evidence,
            } => write!(
                f,
                "child {pid} exited early ({status}); evidence {}",
                evidence.display()
            ),
            Self::Timeout {
                pid,
                operation,
                evidence,
                detail,
            } => write!(
                f,
                "timeout waiting for {operation} on child {pid} (evidence {}): {detail}",
                evidence.display()
            ),
            Self::Protocol(detail) => write!(f, "protocol: {detail}"),
            Self::Reference {
                path,
                expected,
                detail,
            } => write!(
                f,
                "reference binary {} must have SHA256 {expected}: {detail}",
                path.display()
            ),
            Self::Difference {
                observation,
                reference,
                candidate,
            } => write!(
                f,
                "behavior difference for {observation}: reference={reference}; candidate={candidate}"
            ),
            Self::Assertion(detail) => write!(f, "assertion: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<sonic_rs::Error> for Error {
    fn from(error: sonic_rs::Error) -> Self {
        Self::Json(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait ValueExt {
    fn field(&self, key: &str) -> Result<&sonic_rs::Value>;
    fn str_field(&self, key: &str) -> Result<&str>;
    fn u64_field(&self, key: &str) -> Result<u64>;
}

impl ValueExt for sonic_rs::Value {
    fn field(&self, key: &str) -> Result<&sonic_rs::Value> {
        self.get(key)
            .ok_or_else(|| Error::Assertion(format!("missing field {key} in {self}")))
    }

    fn str_field(&self, key: &str) -> Result<&str> {
        self.field(key)?
            .as_str()
            .ok_or_else(|| Error::Assertion(format!("field {key} is not a string in {self}")))
    }

    fn u64_field(&self, key: &str) -> Result<u64> {
        self.field(key)?.as_u64().ok_or_else(|| {
            Error::Assertion(format!("field {key} is not an unsigned integer in {self}"))
        })
    }
}
