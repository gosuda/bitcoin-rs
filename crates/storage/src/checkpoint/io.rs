//! Checkpoint writes and filesystem durability barriers.
//!
//! Under `test`/`test-seam`, publication call sites arm named boundaries
//! through `injected_io` before each plain helper, so the barrier sequence
//! below is exactly what a failpoint run exercises.

use super::CURRENT_FILE;
use super::CheckpointError;
#[cfg(any(test, feature = "test-seam"))]
use super::CheckpointFailpoint;
use super::fs::CheckpointRoot;
use super::fs::sync_dir;
use cap_std::fs::Dir;
use cap_std::fs::File;
use std::io::Write;

/// Fails with `ENOSPC` when `configured` armed `boundary`; called by the
/// publication sequence immediately before the boundary it names.
#[cfg(any(test, feature = "test-seam"))]
pub(crate) fn injected_io(
    configured: Option<CheckpointFailpoint>,
    boundary: CheckpointFailpoint,
) -> std::io::Result<()> {
    if configured == Some(boundary) {
        return Err(std::io::Error::from_raw_os_error(28));
    }
    Ok(())
}

pub(crate) fn write_file(file: &mut File, bytes: &[u8]) -> Result<(), CheckpointError> {
    file.write_all(bytes)?;
    Ok(())
}

pub(crate) fn sync_file(file: &File) -> Result<(), CheckpointError> {
    file.sync_all()?;
    Ok(())
}

pub(crate) fn sync_checkpoint_dir(dir: &Dir) -> Result<(), CheckpointError> {
    sync_dir(dir)?;
    Ok(())
}

pub(crate) fn sync_root(root: &CheckpointRoot) -> Result<(), CheckpointError> {
    root.sync()?;
    Ok(())
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
pub(crate) fn rename_generation(
    root: &CheckpointRoot,
    from: &str,
    to: &str,
) -> Result<(), CheckpointError> {
    root.rename_noreplace(from, to)?;
    Ok(())
}

pub(crate) fn rename_current(root: &CheckpointRoot, from: &str) -> Result<(), CheckpointError> {
    root.rename(from, CURRENT_FILE)?;
    Ok(())
}
