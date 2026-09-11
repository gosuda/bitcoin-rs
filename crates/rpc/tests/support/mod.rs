//! Shared support for the Core parity vertical gate.
//!
//! Module map: [`limits`] holds the enforced ceilings, [`fixture`] the strict
//! bounded corpus loader, [`http`] the status-or-Content-Length response
//! decoder, [`chain`] the deterministic regtest seed chain, [`harness`] the
//! RAII node/server pair, [`compare`] the structural comparator, and
//! [`manifest_check`] the authority check against the const `MANIFEST`.

pub(crate) mod chain;
pub(crate) mod compare;
pub(crate) mod fixture;
pub(crate) mod harness;
pub(crate) mod http;
pub(crate) mod limits;
pub(crate) mod manifest_check;

use std::fmt;

/// The single failure type of the gate: every refusal, ceiling breach,
/// structural divergence or harness error reduces to one named string.
#[derive(Debug)]
pub(crate) struct Failure(pub(crate) String);

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Failure {}

/// Builds a [`Failure`] from anything printable.
#[must_use]
pub(crate) fn fail(message: impl fmt::Display) -> Failure {
    Failure(message.to_string())
}

/// Gate result alias.
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

impl From<serde_json::Error> for Failure {
    fn from(value: serde_json::Error) -> Self {
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
