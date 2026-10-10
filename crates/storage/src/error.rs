use std::fmt::Display;

use crate::ColumnFamily;

/// Errors returned by storage backends.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
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
    /// Persisted data belongs to an incompatible on-disk format.
    #[error("incompatible data: {0}")]
    IncompatibleData(String),
}

impl StorageError {
    /// Converts a backend-specific error into a stable storage error.
    pub fn backend(error: impl Display) -> Self {
        Self::Backend(error.to_string())
    }
}

/// Failure of an explicitly bounded owned-value read.
#[derive(Debug, thiserror::Error)]
pub enum BoundedReadError {
    /// The backend does not provide a pre-copy bound; no unbounded fallback ran.
    #[error("bounded value reads are unavailable for this store")]
    Unsupported,
    /// The stored value exceeded the requested owned-copy limit.
    #[error("stored value has {size} bytes, exceeding the {limit}-byte read limit")]
    Limit {
        /// Stored value length observed before copying.
        size: usize,
        /// Maximum owned value length requested.
        limit: usize,
    },
    /// The underlying read failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
}

pub(crate) fn copy_bounded(bytes: &[u8], limit: usize) -> Result<Vec<u8>, BoundedReadError> {
    if bytes.len() > limit {
        return Err(BoundedReadError::Limit {
            size: bytes.len(),
            limit,
        });
    }
    Ok(bytes.to_vec())
}
