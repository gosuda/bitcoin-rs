use std::fmt::Display;

use crate::ColumnFamily;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("unknown column family {0:?}")]
    UnknownColumnFamily(ColumnFamily),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("backend-specific: {0}")]
    Backend(String),
    #[error("invalid operation: {0}")]
    InvalidOperation(&'static str),
    #[error("incompatible data: {0}")]
    IncompatibleData(String),
    /// A referenced block frame is malformed or truncated. Verification reads
    /// preserve this evidence; availability-only body reads still return `None`.
    #[error("corrupt block frame: {0}")]
    CorruptBlockFrame(&'static str),
}

impl StorageError {
    pub fn backend(error: impl Display) -> Self {
        Self::Backend(error.to_string())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BoundedReadError {
    #[error("bounded value reads are unavailable for this store")]
    Unsupported,
    #[error("stored value has {size} bytes, exceeding the {limit}-byte read limit")]
    Limit { size: usize, limit: usize },
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
