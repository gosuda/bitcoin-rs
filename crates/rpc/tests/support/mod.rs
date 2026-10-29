//! Shared support for the Core parity vertical gate.

pub(crate) mod chain;
pub(crate) mod compare;
pub(crate) mod fixture;
pub(crate) mod harness;
pub(crate) mod http;
pub(crate) mod limits;
pub(crate) mod manifest_check;

use std::fmt;

#[derive(Debug)]
pub(crate) struct Failure(pub(crate) String);

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Failure {}

#[must_use]
pub(crate) fn fail(message: impl fmt::Display) -> Failure {
    Failure(message.to_string())
}

pub(crate) type GateResult<T> = Result<T, Failure>;

impl From<std::io::Error> for Failure {
    fn from(value: std::io::Error) -> Self {
        fail(value)
    }
}

impl From<sonic_rs::Error> for Failure {
    fn from(value: sonic_rs::Error) -> Self {
        fail(value)
    }
}

impl From<fixture::LoadError> for Failure {
    fn from(value: fixture::LoadError) -> Self {
        fail(value)
    }
}

impl From<compare::Mismatch> for Failure {
    fn from(value: compare::Mismatch) -> Self {
        fail(value)
    }
}

impl From<http::HttpError> for Failure {
    fn from(value: http::HttpError) -> Self {
        fail(value)
    }
}
