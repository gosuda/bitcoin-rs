//! Row-value format reporting and marker decoding.

use super::{error::IndexError, reader::Indexer};
use bitcoin_rs_storage::{ColumnFamily, KvStore, WriteBatch};

impl<S: KvStore> Indexer<S> {
    /// Reports whether this index's rows carry transaction positions, adopting
    /// the current format when the index is empty.
    ///
    /// Reading is always correct either way — a row without positions takes the
    /// scan fallback — so this exists to tell an operator which path their node
    /// is on, not to gate correctness. The difference is three orders of
    /// magnitude on history resolution, which is worth a startup line.
    ///
    /// An index with rows but no version marker predates the format and is
    /// reported as [`IndexFormat::Legacy`]. The marker is written only for an
    /// empty index, because that is the only case where every row that will ever
    /// exist is going to be written with positions. Writing it for a populated
    /// legacy index would claim positions that are not there.
    pub fn ensure_format_version(&self) -> Result<IndexFormat, IndexError> {
        match self.read_format_version()? {
            Some(FormatMarker::Version(found)) => {
                return Ok(if found == INDEX_FORMAT_VERSION {
                    IndexFormat::Current
                } else {
                    IndexFormat::Legacy { found: Some(found) }
                });
            }
            Some(FormatMarker::Unreadable { len }) => {
                return Ok(IndexFormat::UnreadableMarker { len });
            }
            None => {}
        }
        if self.has_any_header()? {
            return Ok(IndexFormat::Legacy { found: None });
        }
        let mut batch = self.store.new_batch();
        batch.put(
            ColumnFamily::UtxoMeta,
            INDEX_FORMAT_VERSION_KEY,
            &INDEX_FORMAT_VERSION.to_le_bytes(),
        );
        self.store.write(batch)?;
        Ok(IndexFormat::Current)
    }

    fn read_format_version(&self) -> Result<Option<FormatMarker>, IndexError> {
        let Some(bytes) = self
            .store
            .get(ColumnFamily::UtxoMeta, INDEX_FORMAT_VERSION_KEY)?
        else {
            return Ok(None);
        };
        let Ok(encoded) = <[u8; 4]>::try_from(bytes.as_slice()) else {
            // Reported as its own outcome rather than folded into version 0: an
            // operator told "your index is at version 0" deletes and re-syncs,
            // which is the wrong response to bytes that should be a `u32` and
            // are not.
            return Ok(Some(FormatMarker::Unreadable { len: bytes.len() }));
        };
        Ok(Some(FormatMarker::Version(u32::from_le_bytes(encoded))))
    }

    /// True when the header column family holds at least one row.
    ///
    /// Deliberately not `header_count`: a legacy index takes this branch on
    /// every single start, and counting reads every row in the column family
    /// and allocates an 80-byte array per row — roughly a million of each at
    /// mainnet height — to answer a question that is only ever yes or no.
    fn has_any_header(&self) -> Result<bool, IndexError> {
        let mut rows = self.store.iter_prefix(ColumnFamily::BlockHeaders, &[])?;
        Ok(rows.next().transpose()?.is_some())
    }
}

/// Metadata key marking which row-value format an index was written with.
pub(super) const INDEX_FORMAT_VERSION_KEY: &[u8] = b"index:format_version";

/// Current row-value format.
///
/// Version 1 added transaction byte positions to funding and txid row values;
/// version 2 added positions to spending row values; version 3 narrowed
/// positions to 6 bytes (u24 offset + u24 length); version 0 (unmarked) has
/// empty values.
pub const INDEX_FORMAT_VERSION: u32 = 3;

/// Which row-value format an opened index carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexFormat {
    /// Rows carry transaction positions; resolvers take the fast path.
    Current,
    /// Rows predate transaction positions; resolvers scan whole blocks.
    ///
    /// Correct but far slower. Clearing the index directory and re-syncing
    /// rebuilds it in the current format.
    Legacy {
        /// The version marker found, or `None` when the index carries none.
        found: Option<u32>,
    },
    /// A version marker exists but is not the 4 little-endian bytes of a `u32`.
    ///
    /// Resolvers scan, exactly as for [`Self::Legacy`], but the operator
    /// response differs: this is damaged metadata, not an old index, and
    /// deleting the directory would discard the evidence of whatever wrote it.
    UnreadableMarker {
        /// Byte length of the marker value that failed to decode.
        len: usize,
    },
}

/// What the format-version marker key holds, when it is present at all.
enum FormatMarker {
    /// Four little-endian bytes that decoded to this version.
    Version(u32),
    /// Present, but not a 4-byte little-endian `u32`.
    Unreadable {
        /// Byte length of the value found.
        len: usize,
    },
}
