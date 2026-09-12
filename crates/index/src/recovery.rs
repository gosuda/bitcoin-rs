//! Open-time compatibility recovery for disposable derived index storage.
//!
//! The caller selects and opens the storage backend. This module owns the
//! existing legacy/unsupported-format rebuild fallback; it does not choose
//! data directories, own chainstate, or change the on-disk schema.

use std::sync::Arc;

use crate::{IndexError, IndexWriter};

/// Opens an `IndexWriter` with legacy/unsupported-format recovery.
///
/// Any marker older than the current format 5 full-resets for rebuild: every
/// row family changed, so no in-place upgrade path exists. Cursorless legacy
/// tables reset the same way.
pub fn open_writer<S>(store: &Arc<S>, generation: u64) -> Result<IndexWriter<S>, IndexError>
where
    S: bitcoin_rs_storage::KvStore,
{
    match IndexWriter::open(Arc::clone(store), generation) {
        Ok(writer) => Ok(writer),
        Err(
            error @ (IndexError::LegacyCursorlessIndex
            | IndexError::UnsupportedTxIndexFormatVersion { .. }),
        ) => {
            tracing::warn!(
                %error,
                "resetting incompatible derived transaction index for rebuild"
            );
            IndexWriter::reset_index(store.as_ref(), generation)?;
            IndexWriter::open(Arc::clone(store), generation)
        }
        Err(error) => Err(error),
    }
}
