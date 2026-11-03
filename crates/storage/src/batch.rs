use bytes::Bytes;

use crate::ColumnFamily;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchOp {
    Put {
        cf: ColumnFamily,
        key: Vec<u8>,
        value: Bytes,
    },
    Delete {
        cf: ColumnFamily,
        key: Vec<u8>,
    },
    DeleteRange {
        cf: ColumnFamily,
        start: Vec<u8>,
        end: Vec<u8>,
    },
}

#[derive(Default)]
pub struct BufferedWriteBatch {
    pub(crate) ops: Vec<BatchOp>,
    pub(crate) encoded_bytes: usize,
}

impl BufferedWriteBatch {
    pub fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]) {
        self.put_value(cf, key, Bytes::copy_from_slice(value));
    }

    pub fn put_value(&mut self, cf: ColumnFamily, key: &[u8], value: Bytes) {
        self.encoded_bytes = self.encoded_bytes.saturating_add(key.len() + value.len());
        self.ops.push(BatchOp::Put {
            cf,
            key: key.to_vec(),
            value,
        });
    }

    pub fn delete(&mut self, cf: ColumnFamily, key: &[u8]) {
        self.encoded_bytes = self.encoded_bytes.saturating_add(key.len());
        self.ops.push(BatchOp::Delete {
            cf,
            key: key.to_vec(),
        });
    }

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

    #[must_use]
    pub fn into_ops(self) -> Vec<BatchOp> {
        self.ops
    }
}

#[cfg(all(
    any(feature = "fjall", feature = "redb"),
    any(test, feature = "test-seam")
))]
pub(crate) fn prefix_ops(ops: Vec<BatchOp>) -> std::vec::IntoIter<BatchOp> {
    let mut ops = ops;
    let split = ops.len().div_ceil(2).max(1).min(ops.len());
    ops.truncate(split);
    ops.into_iter()
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
}
