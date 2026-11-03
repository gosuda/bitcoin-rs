use super::{DerivedIndexWorkerError, IndexError, NamespaceRegistry, OpenDerivedIndex};
use bitcoin_rs_storage::checkpoint::fs::{open_data_dir, read_file, sync_dir};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const RESET_INTENT: &[u8] = b"bitcoin-rs-derived-index-reset-v1\n";

pub(super) fn open(
    root: &Path,
    namespace: &str,
    dir: &Path,
    cancelled: impl Fn() -> bool,
    open_store: impl Fn(&Path) -> Result<OpenDerivedIndex, DerivedIndexWorkerError>,
) -> Result<OpenDerivedIndex, DerivedIndexWorkerError> {
    let root = validate_namespace(root, namespace, dir)?;
    let parent = open_data_dir(&root)?;
    let marker = format!(".{namespace}.reset");
    let pending = match read_file(&parent, &marker, 64) {
        Ok(bytes) if bytes == RESET_INTENT => true,
        Ok(_) => return Err(io::Error::other("unrecognized index reset intent").into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if cancelled() {
        return Err(DerivedIndexWorkerError::OpenStopped);
    }
    if !pending {
        match open_store(dir) {
            Err(DerivedIndexWorkerError::Index(
                error @ (IndexError::LegacyCursorlessIndex
                | IndexError::UnsupportedTxIndexFormatVersion { .. }
                | IndexError::FullResetRequired),
            )) => {
                if cancelled() {
                    return Err(DerivedIndexWorkerError::OpenStopped);
                }
                tracing::warn!(%error, dir = %dir.display(), "recreating incompatible derived index namespace for rebuild");
                let mut intent = tempfile::NamedTempFile::new_in(&root)?;
                intent.write_all(RESET_INTENT)?;
                intent.as_file().sync_all()?;
                drop(
                    intent
                        .persist_noclobber(root.join(&marker))
                        .map_err(|error| error.error)?,
                );
                sync_dir(&parent)?;
            }
            result => return result,
        }
    }
    if cancelled() {
        return Err(DerivedIndexWorkerError::OpenStopped);
    }
    validate_namespace(&root, namespace, dir)?;
    match parent.remove_dir_all(namespace) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    parent.create_dir(namespace)?;
    sync_dir(&parent)?;
    if cancelled() {
        return Err(DerivedIndexWorkerError::OpenStopped);
    }
    let opened = open_store(dir)?;
    if cancelled() {
        return Err(DerivedIndexWorkerError::OpenStopped);
    }
    parent.remove_file(&marker)?;
    sync_dir(&parent)?;
    Ok(opened)
}

fn validate_namespace(root: &Path, namespace: &str, dir: &Path) -> io::Result<PathBuf> {
    let root = root.canonicalize()?;
    let expected = NamespaceRegistry::validate_child(&root, namespace)
        .map_err(|reason| io::Error::new(io::ErrorKind::InvalidInput, reason))?;
    if dir.file_name() != Some(std::ffi::OsStr::new(namespace))
        || dir.parent().map(Path::canonicalize).transpose()?.as_ref() != Some(&root)
    {
        return Err(io::Error::other("index namespace is outside its data root"));
    }
    match std::fs::symlink_metadata(dir) {
        Ok(metadata) => {
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || dir.canonicalize()? != expected
            {
                return Err(io::Error::other(
                    "index namespace is not a direct directory",
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(root)
}
