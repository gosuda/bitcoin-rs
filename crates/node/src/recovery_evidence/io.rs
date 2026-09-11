//! Bounded evidence reads and atomic durable witness/marker publication.

use super::EvidenceError;
use super::MAX_FILE_BYTES;
use std::path::Path;

/// Writes a bounded current/previous file pair atomically.
///
/// Protocol:
/// 1. Remove stale temp (`NotFound` is success).
/// 2. Open temp with `create_new` (no-symlink semantics).
/// 3. Write bounded payload + newline.
/// 4. `sync_all` the temp file.
/// 5. Validate current; rotate valid current to `.prev`.
///    Never overwrite a known-valid `.prev` with an invalid current.
/// 6. Rename temp to current.
/// 7. `sync_all` the data-dir root.
/// 8. On error, remove temp best-effort.
///
/// `validate` checks whether the current file's bytes are a valid payload.
/// Only a valid current is rotated to `.prev`; an invalid current is removed
/// without overwriting an existing valid `.prev`.
pub(super) fn write_bounded(
    dir: &Path,
    payload: &str,
    current_name: &str,
    prev_name: &str,
    tmp_name: &str,
    validate: impl Fn(&[u8]) -> bool,
) -> Result<(), EvidenceError> {
    let tmp_path = dir.join(tmp_name);
    let current_path = dir.join(current_name);
    let prev_path = dir.join(prev_name);

    // 1. Remove stale temp.
    match std::fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(EvidenceError::Io(e)),
    }

    // 2-7. Stage and publish the replacement.
    let result = (|| -> Result<(), EvidenceError> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        file.write_all(payload.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);

        // 5. Validate current; rotate valid current to `.prev`.
        // Never overwrite a known-valid `.prev` with an invalid current.
        if current_path.exists() {
            match std::fs::read(&current_path) {
                Ok(data) if data.len() <= MAX_FILE_BYTES && validate(&data) => {
                    // Current is valid; rotate to .prev.
                    let _ = std::fs::remove_file(&prev_path);
                    std::fs::rename(&current_path, &prev_path)?;
                }
                _ => {
                    // Current is invalid or oversized; remove it.
                    // Keep existing .prev (never overwrite valid .prev with invalid current).
                    let _ = std::fs::remove_file(&current_path);
                }
            }
        }

        // 6. Rename temp to current.
        std::fs::rename(&tmp_path, &current_path)?;

        // 7. Fsync the data-dir root.
        sync_dir(dir)?;

        Ok(())
    })();

    if result.is_err() {
        // 8. Best-effort temp cleanup on every returned failure.
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

/// missing or invalid (oversized or unreadable). Never selects by greater
/// height or newer time.
pub(super) fn read_bounded(dir: &Path, current_name: &str, prev_name: &str) -> Option<Vec<u8>> {
    let current_path = dir.join(current_name);
    if let Some(data) = read_and_validate(&current_path) {
        Some(data)
    } else {
        let prev_path = dir.join(prev_name);
        read_and_validate(&prev_path)
    }
}

/// Reads, validates size, and returns the file contents. Returns `None` for
/// missing, oversized, or unreadable files.
pub(super) fn read_and_validate(path: &Path) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(data) if data.len() <= MAX_FILE_BYTES => Some(data),
        Ok(_) => {
            tracing::debug!(path = %path.display(), "evidence file oversized, ignoring");
            None
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::debug!(path = %path.display(), error = %e, "evidence file read error");
            None
        }
    }
}

/// Syncs a directory's metadata to durable storage.
pub(super) fn sync_dir(dir: &Path) -> Result<(), EvidenceError> {
    let f = std::fs::File::open(dir)?;
    f.sync_all()?;
    Ok(())
}
