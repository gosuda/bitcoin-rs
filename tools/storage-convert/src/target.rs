use std::path::Path;

use bitcoin_rs_storage::{BufferedWriteBatch, ColumnFamily, KvStore, RocksDbStore, StorageBackend};
use sha2::{Digest, Sha256};

use crate::error::{ConvertError, EngineOpenError};

const BATCH_TARGET_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
pub(crate) struct FamilyDigest {
    hasher: Sha256,
}

impl FamilyDigest {
    pub(crate) fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    pub(crate) fn update(&mut self, key: &[u8], value: &[u8]) -> Result<(), ConvertError> {
        let key_len = u32::try_from(key.len()).map_err(|_| {
            ConvertError::InvalidOperation("storage key length exceeds u32::MAX".into())
        })?;
        let val_len = u32::try_from(value.len()).map_err(|_| {
            ConvertError::InvalidOperation("storage value length exceeds u32::MAX".into())
        })?;
        self.hasher.update(key_len.to_le_bytes());
        self.hasher.update(key);
        self.hasher.update(val_len.to_le_bytes());
        self.hasher.update(value);
        Ok(())
    }

    pub(crate) fn finalize_hex(self) -> String {
        let hash = self.hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in hash {
            use std::fmt::Write;
            let _ = write!(&mut hex, "{byte:02x}");
        }
        hex
    }
}

pub(crate) struct BatchWriter<S> {
    store: S,
    pending: Option<(BufferedWriteBatch, usize)>,
    has_oversized_row: bool,
}

impl<'a> BatchWriter<Box<dyn FnMut(BufferedWriteBatch) -> Result<(), ConvertError> + 'a>> {
    pub(crate) fn new(store: &'a dyn KvStore) -> Self {
        Self::with_sink(Box::new(|batch| {
            store.write_durable(batch).map_err(ConvertError::Storage)
        }))
    }
}

impl<S> BatchWriter<S>
where
    S: FnMut(BufferedWriteBatch) -> Result<(), ConvertError>,
{
    fn with_sink(store: S) -> Self {
        Self {
            store,
            pending: None,
            has_oversized_row: false,
        }
    }
}

impl<S> BatchWriter<S>
where
    S: FnMut(BufferedWriteBatch) -> Result<(), ConvertError>,
{
    pub(crate) fn put(
        &mut self,
        cf: ColumnFamily,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), ConvertError> {
        let row_bytes = key.len().saturating_add(value.len());
        let needs_pre_flush = self.pending.as_ref().is_some_and(|(_, current_bytes)| {
            current_bytes.saturating_add(row_bytes) > BATCH_TARGET_BYTES
        });
        if needs_pre_flush {
            self.flush()?;
        }
        if row_bytes > BATCH_TARGET_BYTES && self.pending.is_some() {
            return Err(ConvertError::InvalidOperation(
                "an indivisible large row must be written alone".into(),
            ));
        }
        self.has_oversized_row |= row_bytes > BATCH_TARGET_BYTES;

        let should_flush = {
            let (batch, current_bytes) = self
                .pending
                .get_or_insert_with(|| (BufferedWriteBatch::default(), 0));

            batch.put(cf, key, value);
            *current_bytes = current_bytes.saturating_add(row_bytes);
            *current_bytes >= BATCH_TARGET_BYTES
        };

        if should_flush {
            self.flush()?;
        }
        Ok(())
    }

    pub(crate) fn flush(&mut self) -> Result<(), ConvertError> {
        if let Some((batch, current_bytes)) = self.pending.take() {
            if self.has_oversized_row {
                if current_bytes <= BATCH_TARGET_BYTES {
                    return Err(ConvertError::InvalidOperation(
                        "oversized batch state is inconsistent".into(),
                    ));
                }
            } else if current_bytes > BATCH_TARGET_BYTES {
                return Err(ConvertError::InvalidOperation(
                    "ordinary conversion batch exceeds 64 MiB".into(),
                ));
            }
            self.has_oversized_row = false;
            (self.store)(batch)?;
        }
        Ok(())
    }
}

pub(crate) fn compute_destination_digest(
    store: &dyn KvStore,
    cf: ColumnFamily,
) -> Result<(u64, String), ConvertError> {
    let mut digest = FamilyDigest::new();
    let mut count = 0u64;

    let iter = store.iter_prefix(cf, b"")?;
    for item in iter {
        let (key, value) = item?;
        digest.update(&key, &value)?;
        count = count.saturating_add(1);
    }

    Ok((count, digest.finalize_hex()))
}

pub(crate) fn open_destination_store(
    path: &Path,
    engine: StorageBackend,
) -> Result<Box<dyn KvStore>, ConvertError> {
    match engine {
        StorageBackend::RocksDb => {
            let store = RocksDbStore::open(path)
                .map_err(|e| ConvertError::EngineOpen(EngineOpenError::Storage(e)))?;
            Ok(Box::new(store))
        }
        StorageBackend::SurrealKv => {
            #[cfg(feature = "surrealkv")]
            {
                let store =
                    bitcoin_rs_storage::SurrealKvStore::open_with_cache(path, 64 * 1024 * 1024)
                        .map_err(|e| ConvertError::EngineOpen(EngineOpenError::Storage(e)))?;
                Ok(Box::new(store))
            }
            #[cfg(not(feature = "surrealkv"))]
            {
                let _ = path;
                Err(ConvertError::EngineNotCompiled {
                    engine: "surrealkv".to_string(),
                    feature: "surrealkv",
                })
            }
        }
        StorageBackend::Mdbx => {
            #[cfg(feature = "mdbx")]
            {
                let store = bitcoin_rs_storage::MdbxStore::open_with_cache(path, 0)
                    .map_err(|e| ConvertError::EngineOpen(EngineOpenError::Storage(e)))?;
                Ok(Box::new(store))
            }
            #[cfg(not(feature = "mdbx"))]
            {
                let _ = path;
                Err(ConvertError::EngineNotCompiled {
                    engine: "mdbx".to_string(),
                    feature: "mdbx",
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BATCH_TARGET_BYTES, BatchWriter};
    use bitcoin_rs_storage::{BatchOp, BufferedWriteBatch, ColumnFamily};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn oversized_row_flushes_preceding_rows_and_is_written_alone() {
        let mib = 1024 * 1024;
        let preceding_a = vec![1_u8; 30 * mib];
        let preceding_b = vec![2_u8; 30 * mib];
        let oversized = vec![3_u8; 66 * mib];
        let following = vec![4_u8; mib];
        let inputs = [
            (b"undo:block_00000000_0".as_slice(), preceding_a.as_slice()),
            (b"undo:block_00000000_1".as_slice(), preceding_b.as_slice()),
            (b"undo:block_00000001".as_slice(), oversized.as_slice()),
            (b"undo:block_00000002".as_slice(), following.as_slice()),
        ];
        let expected_batches = [
            vec![(inputs[0].0, inputs[0].1), (inputs[1].0, inputs[1].1)],
            vec![inputs[2]],
            vec![inputs[3]],
        ];
        let mut batches = Vec::new();
        {
            let mut writer = BatchWriter::with_sink(|batch: BufferedWriteBatch| {
                let rows = batch
                    .into_ops()
                    .into_iter()
                    .map(|op| match op {
                        BatchOp::Put { key, value, .. } => (key, value.to_vec()),
                        BatchOp::Delete { .. } | BatchOp::DeleteRange { .. } => {
                            panic!("large-row conversion only puts rows")
                        }
                    })
                    .collect::<Vec<_>>();
                batches.push(rows);
                Ok(())
            });
            for (key, value) in inputs {
                let result = writer.put(ColumnFamily::UndoData, key, value);
                assert!(result.is_ok(), "valid rows must be accepted: {result:?}");
            }
            let result = writer.flush();
            assert!(result.is_ok(), "final valid batch must flush: {result:?}");
        }

        assert_eq!(batches.len(), expected_batches.len());
        for (actual, expected) in batches.iter().zip(expected_batches) {
            assert_eq!(actual.len(), expected.len());
            for ((actual_key, actual_value), (expected_key, expected_value)) in
                actual.iter().zip(expected)
            {
                assert_eq!(actual_key, expected_key);
                assert_eq!(actual_value, expected_value);
            }
        }
        assert_eq!(batches[0].len(), 2);
        assert_eq!(batches[1].len(), 1);
        assert_eq!(batches[1][0].1.len(), 66 * mib);
        assert_eq!(batches[2].len(), 1);
        assert_eq!(BATCH_TARGET_BYTES, 64 * mib);
    }

    #[test]
    fn consecutive_oversized_rows_are_written_in_separate_batches() {
        let oversized = vec![7_u8; BATCH_TARGET_BYTES + 1];
        let writes = Arc::new(AtomicUsize::new(0));
        let sink_writes = Arc::clone(&writes);
        let mut writer = BatchWriter::with_sink(move |_batch| {
            sink_writes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let first = writer.put(ColumnFamily::UndoData, b"large-0", &oversized);
        assert!(
            first.is_ok(),
            "single large row must be accepted: {first:?}"
        );
        assert_eq!(
            writes.load(Ordering::SeqCst),
            1,
            "single large row must flush alone"
        );

        let second = writer.put(ColumnFamily::UndoData, b"small", b"pending");
        assert!(
            second.is_ok(),
            "ordinary following row must be accepted: {second:?}"
        );
        let third = writer.put(ColumnFamily::UndoData, b"large-1", &oversized);
        assert!(
            third.is_ok(),
            "pending ordinary row must pre-flush: {third:?}"
        );
        assert_eq!(
            writes.load(Ordering::SeqCst),
            3,
            "ordinary pending row must flush before second large row"
        );

        let fourth = writer.put(ColumnFamily::UndoData, b"large-2", &oversized);
        assert!(
            fourth.is_ok(),
            "an oversized row after a flushed oversized batch must be accepted alone: {fourth:?}"
        );
        assert_eq!(
            writes.load(Ordering::SeqCst),
            4,
            "each oversized row must be written in its own durable batch"
        );
    }
}
