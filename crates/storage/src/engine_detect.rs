use std::path::Path;

use crate::{StorageBackend, StorageError};

/// Marker file name for SurrealKV detection.
pub const SURREALKV_MARKER: &str = "manifest";

/// Detects the storage engine present in `dir`.
pub fn detect_engine(dir: &Path) -> Result<Option<StorageBackend>, StorageError> {
    if !dir.exists() {
        return Ok(None);
    }

    let read_dir = std::fs::read_dir(dir).map_err(StorageError::Io)?;
    let mut entries = Vec::new();

    for entry in read_dir {
        let entry = entry.map_err(StorageError::Io)?;
        let file_name = entry.file_name();
        let name = file_name
            .into_string()
            .map_err(|_| StorageError::IncompatibleData("non-UTF-8 file name".to_owned()))?;
        entries.push(name);
    }

    if entries.is_empty() {
        return Ok(None);
    }

    let has_mdbx = entries.iter().any(|name| name == "mdbx.dat");

    let has_current = entries.iter().any(|name| name == "CURRENT");
    let has_options = entries.iter().any(|name| name.starts_with("OPTIONS-"));
    let has_rocksdb = has_current && has_options;

    let has_surreal_marker = entries.iter().any(|name| name == SURREALKV_MARKER);
    let has_surreal_engine = entries.iter().any(|name| name == "ENGINE")
        && std::fs::read_to_string(dir.join("ENGINE"))
            .is_ok_and(|content| content.trim() == "surrealkv");
    let has_surrealkv = has_surreal_marker || has_surreal_engine;

    let mut detected = None;
    let mut count = 0usize;
    if has_mdbx {
        detected = Some(StorageBackend::Mdbx);
        count = count.saturating_add(1);
    }
    if has_rocksdb {
        detected = Some(StorageBackend::RocksDb);
        count = count.saturating_add(1);
    }
    if has_surrealkv {
        detected = Some(StorageBackend::SurrealKv);
        count = count.saturating_add(1);
    }

    if count > 1 {
        return Err(StorageError::IncompatibleData(
            "multiple recognized storage engines detected in directory".to_owned(),
        ));
    }

    if let Some(backend) = detected {
        return Ok(Some(backend));
    }

    Err(StorageError::IncompatibleData(
        "unknown engine files".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::detect_engine;
    use crate::StorageError;

    #[test]
    fn current_and_manifest_without_options_are_incompatible() -> Result<(), StorageError> {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join("CURRENT"), b"MANIFEST-000001\n")?;
        std::fs::write(dir.path().join("MANIFEST-000001"), b"foreign manifest")?;

        assert!(matches!(
            detect_engine(dir.path()),
            Err(StorageError::IncompatibleData(_))
        ));
        assert_eq!(std::fs::read_dir(dir.path())?.count(), 2);
        assert_eq!(
            std::fs::read(dir.path().join("CURRENT"))?,
            b"MANIFEST-000001\n"
        );
        assert_eq!(
            std::fs::read(dir.path().join("MANIFEST-000001"))?,
            b"foreign manifest"
        );
        Ok(())
    }

    #[test]
    fn rocksdb_checkpoint_is_detected_and_loads_row_without_identity() -> Result<(), StorageError> {
        use crate::{ColumnFamily, KvStore, RocksDbStore, StorageBackend};

        let dir = tempfile::tempdir()?;
        let source = RocksDbStore::open(dir.path().join("source"))?;
        let checkpoint = dir.path().join("checkpoint");
        source.put(
            ColumnFamily::UtxoMeta,
            b"checkpoint-key",
            b"checkpoint-value",
        )?;
        source.checkpoint(&checkpoint)?;
        source.put(
            ColumnFamily::UtxoMeta,
            b"checkpoint-key",
            b"source-only-value",
        )?;

        assert!(!checkpoint.join("IDENTITY").exists());
        assert_eq!(detect_engine(&checkpoint)?, Some(StorageBackend::RocksDb));
        let restored = crate::checkpoint::open_checkpoint_store(&checkpoint)?;
        assert_eq!(
            restored.get(ColumnFamily::UtxoMeta, b"checkpoint-key")?,
            Some(b"checkpoint-value".to_vec())
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_names_are_incompatible_not_empty() -> Result<(), StorageError> {
        use std::os::unix::ffi::OsStrExt as _;
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join("junk"), b"foreign")?;
        let Err(StorageError::IncompatibleData(_)) = detect_engine(dir.path()) else {
            panic!("ascii junk must be incompatible");
        };
        std::fs::remove_file(dir.path().join("junk"))?;
        let foreign = std::ffi::OsStr::from_bytes(b"\xff\xfenon-utf8");
        std::fs::write(dir.path().join(foreign), b"foreign")?;
        let entries = std::fs::read_dir(dir.path())?.count();
        assert_eq!(entries, 1);
        let Err(StorageError::IncompatibleData(_)) = detect_engine(dir.path()) else {
            panic!("non-UTF-8 names must be incompatible");
        };
        Ok(())
    }
}
