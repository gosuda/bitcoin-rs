use bytes::Bytes;

use crate::ColumnFamily;

/// One recorded mutation inside a [`BufferedWriteBatch`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchOp {
    /// Inserts or replaces `key` with `value` in `cf`.
    Put {
        /// Target column family.
        cf: ColumnFamily,
        /// Row key.
        key: Vec<u8>,
        /// Row value.
        value: Bytes,
    },
    /// Deletes `key` from `cf`.
    Delete {
        /// Target column family.
        cf: ColumnFamily,
        /// Row key.
        key: Vec<u8>,
    },
    /// Deletes every key in `[start, end)` from `cf`.
    DeleteRange {
        /// Target column family.
        cf: ColumnFamily,
        /// First deleted key.
        start: Vec<u8>,
        /// One past the last deleted key.
        end: Vec<u8>,
    },
}

/// Ordered, backend-neutral operations awaiting an engine commit.
///
/// The batch is the only recorder: it appends [`BatchOp`] values through
/// `put`, `put_value`, `delete`, and `delete_range`, and a backend applies
/// the recorded sequence atomically through `KvStore::write` and its durable
/// variants.
///
/// INVARIANT: the recorded sequence keeps its append order, and every backend
/// applies the operations in that order inside one atomic commit.
#[derive(Default)]
pub struct BufferedWriteBatch {
    pub(crate) ops: Vec<BatchOp>,
    /// Supplied key, value, and range-bound bytes, not physical engine I/O.
    pub(crate) encoded_bytes: usize,
}

impl BufferedWriteBatch {
    /// Inserts or replaces `key` with `value` in `cf`.
    ///
    /// PRE: none. POST: the batch records one `BatchOp::Put` after its
    /// recorded operations. INVARIANT: append order equals commit order.
    pub fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]) {
        self.put_value(cf, key, Bytes::copy_from_slice(value));
    }

    /// Inserts or replaces `key` with an owned `value` in `cf`.
    ///
    /// PRE: none. POST: the batch records one `BatchOp::Put` after its
    /// recorded operations. INVARIANT: append order equals commit order.
    pub fn put_value(&mut self, cf: ColumnFamily, key: &[u8], value: Bytes) {
        self.encoded_bytes = self.encoded_bytes.saturating_add(key.len() + value.len());
        self.ops.push(BatchOp::Put {
            cf,
            key: key.to_vec(),
            value,
        });
    }

    /// Deletes `key` from `cf`.
    ///
    /// PRE: none. POST: the batch records one `BatchOp::Delete` after its
    /// recorded operations. INVARIANT: append order equals commit order.
    pub fn delete(&mut self, cf: ColumnFamily, key: &[u8]) {
        self.encoded_bytes = self.encoded_bytes.saturating_add(key.len());
        self.ops.push(BatchOp::Delete {
            cf,
            key: key.to_vec(),
        });
    }

    /// Deletes keys in `[start, end)` from `cf`.
    ///
    /// PRE: none. POST: the batch records one `BatchOp::DeleteRange` after
    /// its recorded operations. INVARIANT: append order equals commit order.
    pub fn delete_range(&mut self, cf: ColumnFamily, start: &[u8], end: &[u8]) {
        self.encoded_bytes = self
            .encoded_bytes
            .saturating_add(start.len())
            .saturating_add(end.len());
        self.ops.push(BatchOp::DeleteRange {
            cf,
            start: start.to_vec(),
            end: end.to_vec(),
        });
    }

    /// Consumes the batch and returns its recorded operations.
    ///
    /// PRE: none. POST: returns every recorded [`BatchOp`] in the order the
    /// backend applies it. INVARIANT: consuming it leaves no batch from
    /// which those operations can be read again.
    #[must_use]
    pub fn into_ops(self) -> Vec<BatchOp> {
        self.ops
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_metric_counts_range_bounds_and_mixed_operations() {
        let mut batch = BufferedWriteBatch::default();
        batch.delete_range(ColumnFamily::BlockBodies, b"a", b"zz");
        assert_eq!(batch.encoded_bytes, 3);
        batch.put(ColumnFamily::BlockBodies, b"key", b"value");
        batch.delete(ColumnFamily::BlockBodies, b"gone");
        assert_eq!(batch.encoded_bytes, 15);
    }

    #[test]
    fn into_ops_returns_every_recorded_operation_in_commit_order() {
        let mut batch = BufferedWriteBatch::default();
        batch.put(ColumnFamily::BlockBodies, b"k", b"v");
        batch.delete(ColumnFamily::UtxoMeta, b"d");
        batch.delete_range(ColumnFamily::TxConfirmed, b"a", b"b");
        let ops = batch.into_ops();
        assert_eq!(
            ops,
            vec![
                BatchOp::Put {
                    cf: ColumnFamily::BlockBodies,
                    key: b"k".to_vec(),
                    value: Bytes::from_static(b"v"),
                },
                BatchOp::Delete {
                    cf: ColumnFamily::UtxoMeta,
                    key: b"d".to_vec(),
                },
                BatchOp::DeleteRange {
                    cf: ColumnFamily::TxConfirmed,
                    start: b"a".to_vec(),
                    end: b"b".to_vec(),
                },
            ]
        );
    }
}
