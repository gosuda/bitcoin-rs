use std::fmt::Display;

use crate::ColumnFamily;

/// Errors returned by storage backends.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The requested backend feature was not enabled for this build.
    #[error("backend `{backend}` not enabled at build time")]
    BackendNotEnabled {
        /// Backend feature name.
        backend: &'static str,
    },
    /// A column family is unknown to the selected backend.
    #[error("unknown column family {0:?}")]
    UnknownColumnFamily(ColumnFamily),
    /// Filesystem or OS I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Backend-specific failure converted to a stable storage error.
    #[error("backend-specific: {0}")]
    Backend(String),
    /// Input would violate a backend-independent storage invariant.
    #[error("invalid operation: {0}")]
    InvalidOperation(&'static str),
}

impl StorageError {
    /// Converts a backend-specific error into a stable storage error.
    pub fn backend(error: impl Display) -> Self {
        Self::Backend(error.to_string())
    }
}
